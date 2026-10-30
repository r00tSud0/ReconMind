"""
ReconMind agent brain: the ReAct loop.

    Reason  -> the model reads the conversation and decides what to do
    Act     -> it asks for a tool (tool_use block)
    Observe -> ToolBox runs it and the result goes back as a tool_result
    repeat until the model answers with no tool call, or MAX_STEPS is hit

The loop talks to the LLM through the raw Anthropic SDK (no LangChain). The
client is passed in, so tests can drive the loop with a scripted fake model
and no API key.
"""

import os

from reconmind.agent.prompts import SYSTEM_PROMPT, first_user_message
from reconmind.agent.tools import TOOL_SPECS, ToolBox

DEFAULT_MODEL = "claude-sonnet-5-5"
MAX_STEPS = 12          # hard cap on model turns, so a run can never loop forever
MAX_TOKENS = 2048


def _say(trace, kind, text):
    """Print one line of the live ReAct trace."""
    if trace:
        print("[{k:<7}] {t}".format(k=kind, t=text))


def _short(text, limit=300):
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit] + " ..."


def run_agent(target, client=None, model=None, trace=True):
    """
    Run one ReAct session against target.

    Returns (toolbox, summary_text). toolbox.scan holds the structured results
    for the report; summary_text is the model's final analyst summary.
    """
    if client is None:
        import anthropic  # imported here so tests don't need the package
        client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY
    model = model or os.environ.get("RECONMIND_MODEL", DEFAULT_MODEL)

    tools = ToolBox(target)
    messages = [{"role": "user", "content": first_user_message(target)}]

    for step in range(1, MAX_STEPS + 1):
        response = client.messages.create(
            model=model,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            tools=TOOL_SPECS,
            messages=messages,
        )
        messages.append({"role": "assistant", "content": response.content})

        tool_uses = [b for b in response.content if b.type == "tool_use"]
        text = "\n".join(b.text for b in response.content if b.type == "text").strip()

        # No tool call means the model is finished and this is the summary.
        if response.stop_reason != "tool_use" or not tool_uses:
            _say(trace, "DONE", "agent finished after {n} step(s)".format(n=step))
            return tools, text

        if text:
            _say(trace, "THOUGHT", _short(text))

        results = []
        for block in tool_uses:
            _say(trace, "ACTION", "{n}({a})".format(n=block.name, a=block.input))
            observation, is_error = tools.call(block.name, block.input)
            _say(trace, "ERROR" if is_error else "OBSERVE", _short(observation))
            results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": observation,
                "is_error": is_error,
            })
        messages.append({"role": "user", "content": results})

    _say(trace, "STOP", "hit MAX_STEPS={m}, stopping".format(m=MAX_STEPS))
    return tools, ("The agent hit its step limit ({m}) before finishing. "
                   "The tables below are the raw tool results.".format(m=MAX_STEPS))
