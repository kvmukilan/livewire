# Frozen-source CI records

Both retained GitHub CI runs completed successfully for commit `99600ceae7c179eb758895cf6657d646ae1fe466`: [pull request run 36627049037](https://github.com/kvmukilan/livewire/actions/runs/36627049037) and [push run 36627037090](https://github.com/kvmukilan/livewire/actions/runs/36627037090). The JSON records retain job and step conclusions, timestamps, URLs, and the exact head commit.

These records establish CI for the frozen executable source. Final documentation/evidence commits also require successful CI before merge. Tag publication runs the [release workflow](https://github.com/kvmukilan/livewire/actions/workflows/release.yml), which independently validates qualification, runs compatibility/security checks, reproduces artifact hashes and publishes/verifies assets. Its actual GitHub status is the publication evidence; these earlier runs do not claim that future steps have already succeeded.
