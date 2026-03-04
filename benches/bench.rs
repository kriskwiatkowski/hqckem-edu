// SPDX-License-Identifier: MIT
// SPDX-FileContributor: Kris Kwiatkowski

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hqc::{HqcParams, generate_key};

fn benchmark_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("keygen");

    let parameter_sets = ["HQC-128", "HQC-192", "HQC-256"];
    let seed = vec![0u8; 32];

    for param_name in parameter_sets.iter() {
        let param = HqcParams::new(param_name).unwrap();
        group.bench_with_input(
            BenchmarkId::from_parameter(param_name),
            &param,
            |b, param| {
                b.iter(|| {
                    let mut pk = vec![0u8; 7237];
                    let mut sk = vec![0u8; 7333];
                    generate_key(black_box(param), black_box(&seed), &mut pk, &mut sk)
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    benchmark_keygen,
    //benchmark_encaps,
    //benchmark_decaps
);
criterion_main!(benches);
