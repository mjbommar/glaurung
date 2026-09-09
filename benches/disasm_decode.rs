use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use glaurung::core::address::{Address, AddressKind};
use glaurung::core::binary::Endianness;
use glaurung::core::disassembler::{Architecture, Disassembler};
use glaurung::disasm::capstone::CapstoneDisassembler;
use glaurung::disasm::native_aarch64::NativeAarch64Disassembler;

const LLVM_TEST_BRANCHES: [[u8; 4]; 4] = [
    [0x20, 0x00, 0x00, 0x36],
    [0xff, 0xff, 0xff, 0x37],
    [0xf4, 0xff, 0x03, 0xb6],
    [0x1e, 0x00, 0xfc, 0xb7],
];

fn native_slice_vectors() -> Vec<[u8; 4]> {
    let corpora = [
        include_str!("../tests/corpora/capstone/aarch64-native-slice.json"),
        include_str!("../tests/corpora/capstone/aarch64-gicv3-regs.json"),
        include_str!("../tests/corpora/capstone/aarch64-trace-regs.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-scalar-abs.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-scalar-neg.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-scalar-add-sub.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-scalar-shift.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-scalar-reduce-pairwise.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-scalar-saturating-add-sub.json"),
        include_str!(
            "../tests/corpora/capstone/aarch64-neon-scalar-saturating-rounding-shift.json"
        ),
        include_str!("../tests/corpora/capstone/aarch64-neon-scalar-saturating-shift.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-scalar-rounding-shift.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-scalar-compare.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-scalar-fp-compare.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-scalar-extract-narrow.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-scalar-recip.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-scalar-mul.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-scalar-by-elem-mul.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-scalar-by-elem-mla.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-scalar-by-elem-saturating-mla.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-scalar-by-elem-saturating-mul.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-scalar-dup.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-scalar-cvt.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-scalar-shift-imm.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-extract.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-frsqrt-frecp.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-add-pairwise.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-rounding-halving-add.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-rounding-shift.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-saturating-shift.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-saturating-rounding-shift.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-shift-left-long.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-facge-facgt.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-crypto.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-bitwise-instructions.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-mla-mls-instructions.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-add-sub-instructions.json"),
        include_str!("../tests/corpora/capstone/aarch64-neon-tbl.json"),
    ];
    let mut vectors = Vec::new();
    for source in corpora {
        let corpus: serde_json::Value =
            serde_json::from_str(source).expect("checked-in decoder corpus");
        vectors.extend(
            corpus["vectors"]
                .as_array()
                .expect("corpus vectors")
                .iter()
                .map(|vector| -> [u8; 4] {
                    vector["bytes"]
                        .as_array()
                        .expect("vector bytes")
                        .iter()
                        .map(|byte| byte.as_u64().expect("byte") as u8)
                        .collect::<Vec<_>>()
                        .try_into()
                        .expect("one A64 instruction")
                }),
        );
    }
    vectors.extend(LLVM_TEST_BRANCHES);
    vectors
}

fn address() -> Address {
    Address::new(AddressKind::VA, 0x1000, 64, None, None).unwrap()
}

fn decode_native_slice(c: &mut Criterion) {
    let vectors = native_slice_vectors();
    let mut group = c.benchmark_group(format!("aarch64_native_slice_decode_{}", vectors.len()));
    group.throughput(Throughput::Elements(vectors.len() as u64));
    let address = address();
    let native = NativeAarch64Disassembler::new(Endianness::Little);
    let capstone = CapstoneDisassembler::new(Architecture::ARM64, Endianness::Little).unwrap();

    group.bench_function("glaurung_native", |b| {
        b.iter(|| {
            for bytes in &vectors {
                black_box(
                    native
                        .disassemble_instruction(black_box(&address), black_box(bytes))
                        .unwrap(),
                );
            }
        })
    });
    group.bench_function("capstone_adapter", |b| {
        b.iter(|| {
            for bytes in &vectors {
                black_box(
                    capstone
                        .disassemble_instruction(black_box(&address), black_box(bytes))
                        .unwrap(),
                );
            }
        })
    });
    group.finish();
}

criterion_group!(benches, decode_native_slice);
criterion_main!(benches);
