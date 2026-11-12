# evaluation

This folder holds the code that trains and tests the ATT&CK mapper experiment
(Model A, a prompted LLM, and Model B, a fine tuned SciBERT). The ReconMind
tool never uses anything in here. Code under `reconmind/` must never import
from `evaluation/`.

## Layout

```
evaluation/
  attack_mapper/      metrics.py, prompted_mapper.py, finetune_utils.py
  scripts/            prepare_tram_data.py, eval_prompted.py
  notebooks/          train_attack_mapper.ipynb (Model B, runs in Colab)
  tests/              offline tests for the code above
  data/tram/          TRAM splits written by prepare_tram_data.py (not committed)
  results/            metrics JSON files for each model run
  results/raw/        per sentence outputs (not committed)
```

## How to run

Run every command from the repo root.

1. Prepare the TRAM data. This downloads TRAM pinned to one commit, checks
   its SHA-256 and writes the splits to `evaluation/data/tram/`:

   ```
   python3 evaluation/scripts/prepare_tram_data.py
   ```

2. Score Model A (prompted LLM). Provider settings come from `.env` or flags,
   the same as the agent:

   ```
   python3 evaluation/scripts/eval_prompted.py --provider NAME --model ID
   ```

   Run it again to resume after a rate limit. See the script's docstring for
   all flags.

3. Train Model B in Colab. Push the `attack-mapper` branch first, because the
   notebook clones it from GitHub. Then open:

   https://colab.research.google.com/github/r00tSud0/ReconMind/blob/attack-mapper/evaluation/notebooks/train_attack_mapper.ipynb

   Choose a T4 GPU, then Runtime, Run all. Download the metrics file at the
   end and put it in `evaluation/results/`.

4. Run the tests (offline, no key or network needed):

   ```
   python3 -m unittest discover -s evaluation/tests -t . -v
   ```

## Collect the ReconMind test set

Build the hand labeling queue from a real scan of an authorized target. This
appends one line per open port to
`evaluation/data/reconmind_eval/findings.jsonl` and saves the full scan under
`evaluation/data/reconmind_eval/scans/`. Findings are questions only, with no
`labels` field; the ATT&CK answer key is kept in a separate file:

```
python3 evaluation/scripts/collect_findings.py TARGET [--all-ports]
```

To rebuild findings from a scan saved earlier, without scanning or touching
the network, pass the scan file instead of TARGET:

```
python3 evaluation/scripts/collect_findings.py --from-scan evaluation/data/reconmind_eval/scans/FILE.json
```

## Score the ReconMind test set

1. Predict with Model B in Colab (CPU is fine). It loads the run 2 model from
   your Google Drive. Push the `attack-mapper` branch first, then open:

   https://colab.research.google.com/github/r00tSud0/ReconMind/blob/attack-mapper/evaluation/notebooks/predict_reconmind_exam.ipynb

   Run all, then put the downloaded
   `finetuned_scibert_run2_reconmind_exam.jsonl` in `evaluation/results/raw/`.

2. Run Model A and score both models against `labels.jsonl`:

   ```
   python3 evaluation/scripts/score_reconmind_exam.py [--provider NAME] [--model ID] [--skip-model-a]
   ```

   Model A resumes after a rate limit like `eval_prompted.py`.
   `--skip-model-a` sends nothing and only scores saved answers. Results go
   to `evaluation/results/reconmind_exam_metrics_run2_tram50.json`, and the
   version 1 answer key scores go to
   `evaluation/results/reconmind_exam_metrics_run2_tram50_labels_v1.json`.
   Both are scored two ways:
   `all_labels` (TRAM's 50 IDs plus every ID in the answer key) and
   `tram50_only` (gold filtered to TRAM's 50).

## Prepare run 3 training data

Run 3 trains Model B on data that looks like ReconMind's findings: ATT&CK
v20.0 procedure examples, MITRE CTID KEV and CVE mappings (CVE text from
cvelistV5), Exploit-DB titles written in ReconMind's finding format, and
TRAM's train and val splits. Every source is pinned to one commit and checked
against its SHA-256. Pass your local Exploit-DB `files_exploits.csv`:

```
python3 evaluation/scripts/prepare_run3_data.py --exploitdb-csv PATH
```

Exploit IDs in the ReconMind test set and their CVEs are removed from every
source, and sentences equal to a TRAM test or eval sentence are removed. The
answer key is never read. Outputs go to `evaluation/data/run3/` (not
committed): `train.jsonl`, `val.jsonl`, `labels.json` and `manifest.json`.
The manifest is also copied to `evaluation/results/run3_data_manifest.json`.
Downloads are cached under `evaluation/data/run3/cache/`, so a second run
works offline.

## Run 3

Run 3 trains Model B on the run 3 data in its own notebook. Run 2's notebook
is unchanged.

1. Prepare the data as above, then commit
   `evaluation/results/run3_data_manifest.json` and push the `attack-mapper`
   branch. Its `outputs` section holds the SHA-256 of `train.jsonl`,
   `val.jsonl` and `labels.json`.
2. Upload those three files from `evaluation/data/run3/` to the Drive folder
   `MyDrive/ReconMind/run3_data/`.
3. Open the notebook in Colab, choose a T4 GPU, then Runtime, Run all:

   https://colab.research.google.com/github/r00tSud0/ReconMind/blob/attack-mapper/evaluation/notebooks/train_attack_mapper_run3.ipynb

   It stops if a file in Drive does not match the manifest. It trains up to
   12 epochs (patience 3), picks the epoch and threshold on run 3's val
   split, and scores TRAM's eval set two ways: `tram50_filtered` (predictions
   limited to TRAM's 50, comparable to run 2 and Model A) and `unfiltered`
   (IDs outside TRAM's 50 count as out of set). It also predicts the ReconMind
   findings. The model is saved to `MyDrive/ReconMind/scibert_attack_mapper_run3`.
4. Put the downloaded `finetuned_scibert_run3_metrics.json` in
   `evaluation/results/` and `finetuned_scibert_run3_reconmind_exam.jsonl` in
   `evaluation/results/raw/`, then score:

   ```
   python3 evaluation/scripts/score_reconmind_exam.py --model-b-run run3 [--model-a-labels tram50|run3] [--skip-model-a]
   ```

   `--model-a-labels run3` gives Model A run 3's label table. Its raw file
   ends in `_run3labels.jsonl`, so it never mixes with the TRAM 50 one.
   Results go to
   `evaluation/results/reconmind_exam_metrics_<model b run>_<model a labels>.json`;
   with no flags that is `reconmind_exam_metrics_run2_tram50.json`. The
   `all_labels` label set is TRAM's 50 plus Model B's label set plus every
   gold ID.

## Where results go

- `evaluation/results/<run>_metrics.json`: headline and per technique scores
  for each run. These are committed.
- `evaluation/results/raw/<run>.jsonl`: one line per eval sentence. Not
  committed. Model B's raw file is also copied to your Google Drive folder.
