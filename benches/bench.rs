// SPDX-License-Identifier: MIT
// SPDX-FileContributor: Kris Kwiatkowski

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use criterion::measurement::Measurement;
use criterion_cycles_per_byte::CyclesPerByte;

use hqc::{HqcParams, generate_key, encaps, decaps};

const PARAMETER_SETS: [&str; 3] = ["HQC-128", "HQC-192", "HQC-256"];

fn benchmark_keygen<M: Measurement>(c: &mut Criterion<M>) {
    let mut group = c.benchmark_group("keygen");

    // Set throughput to 1 key generation per second
    group.throughput(Throughput::Elements(1));

    let seed = vec![0u8; 32];

    for param_name in PARAMETER_SETS.iter() {
        let param = HqcParams::new(param_name).unwrap();
        group.bench_with_input(
            BenchmarkId::from_parameter(param_name),
            &param,
            |b, param| {
                let mut pk = vec![0u8; 7237];
                let mut sk = vec![0u8; 7333];
                b.iter(|| {
                    generate_key(param, &seed, &mut pk, &mut sk)
                });
            },
        );
    }

    group.finish();
}

fn benchmark_encaps<M: Measurement>(c: &mut Criterion<M>) {
    let mut group = c.benchmark_group("encaps");

    // Set throughput to 1 encapsulation per second
    group.throughput(Throughput::Elements(1));

    let seed_keygen = vec![0u8; 32];

    for param_name in PARAMETER_SETS.iter() {
        let p = HqcParams::new(param_name).unwrap();
        let mut pk = vec![0u8; 7237];
        let mut sk = vec![0u8; 7333];
        generate_key(&p, &seed_keygen, &mut pk, &mut sk);

        group.bench_with_input(
            BenchmarkId::from_parameter(param_name),
            &(p, pk),
            |b, (p, pk)| {
                let mut ct = vec![0u8; 14_421];
                let mut ss = vec![0u8; 32];
                let seed_encaps = vec![0u8; 48];
                b.iter(|| {
                    encaps(p, &seed_encaps, pk, &mut ss, &mut ct)
                });
            },
        );
    }

    group.finish();
}

fn benchmark_decaps<M: Measurement>(c: &mut Criterion<M>) {
    let mut group = c.benchmark_group("decaps");

    // Set throughput to 1 decapsulation per second
    group.throughput(Throughput::Elements(1));

    let seed_keygen = vec![0u8; 32];
    for param_name in PARAMETER_SETS.iter() {
        let p = HqcParams::new(param_name).unwrap();
        let mut pk = vec![0u8; 7237];
        let mut sk = vec![0u8; 7333];
        let mut ct = vec![0u8; 14_421];
        let mut ss1: Vec<u8> = vec![0u8; 32];
        let seed_encaps = vec![0u8; 48];
        generate_key(&p, &seed_keygen, &mut pk, &mut sk);
        encaps(&p, &seed_encaps, &pk, &mut ss1, &mut ct);

        group.bench_with_input(
            BenchmarkId::from_parameter(param_name),
            &(p, sk, ct),
            |b, (p, sk, ct)| {
                let mut ss: Vec<u8> = vec![0u8; 32];
                b.iter(|| {
                    decaps(p, &sk, &ct, &mut ss)
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    name = benches_cycles;
    config = Criterion::default().with_measurement(CyclesPerByte);
    targets = benchmark_keygen, benchmark_encaps, benchmark_decaps
);

criterion_main!(benches_cycles);
