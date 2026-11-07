# Native full workspace suite — Kaggle Linux run, 7 November 2026

- Kernel: umirbayulgaisha/af-native-full-workspace-test-1106, version 9
  (versions 1-8: mount-layout and rustfmt bootstrap iterations, retained on Kaggle)
- Dataset: umirbayulgaisha/af-native-src-1106, version 2
  (rfd windows-gate + behavioral checker source; SHA of source tree matches
  experimental d27e42e working tree at packaging time)
- Environment: Kaggle CPU kernel, 4 vCPU, internet on, rustup stable minimal
  + rustfmt component, CARGO_INCREMENTAL=0, CARGO_PROFILE_DEV_DEBUG=0,
  cargo test --workspace --jobs 4
- Result (summary.json): fmt_exit 0, test_exit 0, suites_ok 31,
  passed_total 354, failed_markers 0
- Provider calls: 0. No secrets inside kernel/dataset/evidence.

This is the fresh full-suite gate the local 3.4 GiB machine could not run;
it also proves the Linux build without the Windows-only rfd picker.
