"use strict";

const { expect } = require("chai");
const fs = require("fs");
const os = require("os");
const pth = require("path");
const zlib = require("zlib");
const rimraf = require("rimraf");
const Zip = require("../adm-zip");
const Utils = require("../util");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of (crc-invalid unless `crc` is given) payload.
// crc defaults to 0, deliberately wrong: alloc used to happen before the crc check
function craftBomb(declaredSize, method, content, crc = 0) {
    const name = Buffer.from("a");
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });
});

describe("decompression bomb (declared size) - read APIs - CVE-2026-39244", () => {
    // 0xFFFFFFFF (~4 GB) is the largest size a classic (non zip64) header can declare.
    const DECLARED = 0xffffffff;
    // Nothing allocated while reading these ~100 byte archives may come anywhere
    // near the declared size: an allocation above this limit can only come from
    // trusting the size field, so it is refused before it can exhaust memory.
    const ALLOC_LIMIT = 64 * 1024 * 1024;
    const payload = Buffer.from("hello");
    const payloadCrc = Utils.crc32(payload);
    const storedBomb = () => new Zip(craftBomb(DECLARED, 0 /* STORED */, payload, payloadCrc));
    const deflatedBomb = () => new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, zlib.deflateRawSync(payload), payloadCrc));

    let originalAlloc = null;
    let oversized = [];

    beforeEach(() => {
        oversized = [];
        originalAlloc = Buffer.alloc;
        Buffer.alloc = function (size) {
            if (size > ALLOC_LIMIT) {
                oversized.push(size);
                throw new RangeError("oversized Buffer.alloc(" + size + ") driven by the declared entry size");
            }
            return originalAlloc.apply(this, arguments);
        };
    });

    afterEach(() => {
        Buffer.alloc = originalAlloc;
    });

    it("readFile returns only the stored bytes of an over-declared STORED entry", () => {
        const data = storedBomb().readFile("a");
        expect(oversized).to.eql([]);
        expect(data.equals(payload)).to.equal(true);
    });

    it("readFile returns only the inflated bytes of an over-declared DEFLATED entry", () => {
        const data = deflatedBomb().readFile("a");
        expect(oversized).to.eql([]);
        expect(data.equals(payload)).to.equal(true);
    });

    it("rejects a crc-invalid over-declared STORED entry with a CRC error, not a declared-size allocation", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, payload));
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        expect(oversized).to.eql([]);
    });

    it("rejects a crc-invalid over-declared DEFLATED entry with a CRC error, not a declared-size allocation", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, zlib.deflateRawSync(payload)));
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        expect(oversized).to.eql([]);
    });

    it("readAsText and test() do not allocate the declared size", () => {
        expect(storedBomb().readAsText("a")).to.equal("hello");
        expect(deflatedBomb().readAsText("a")).to.equal("hello");
        expect(storedBomb().test()).to.equal(true);
        expect(deflatedBomb().test()).to.equal(true);
        expect(oversized).to.eql([]);
    });

    it("readFileAsync returns only the stored bytes of an over-declared STORED entry", (done) => {
        storedBomb().readFileAsync("a", (data, err) => {
            try {
                expect(err).to.equal(undefined);
                expect(oversized).to.eql([]);
                expect(data.equals(payload)).to.equal(true);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("readFileAsync returns only the inflated bytes of an over-declared DEFLATED entry", (done) => {
        deflatedBomb().readFileAsync("a", (data, err) => {
            try {
                expect(err).to.equal(undefined);
                expect(oversized).to.eql([]);
                expect(data.equals(payload)).to.equal(true);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    describe("extraction", () => {
        let target = null;

        beforeEach(() => {
            target = fs.mkdtempSync(pth.join(os.tmpdir(), "adm-zip-bomb-"));
        });

        afterEach(() => {
            rimraf.sync(target);
        });

        it("extractAllTo writes only the real bytes of over-declared entries", () => {
            storedBomb().extractAllTo(pth.join(target, "stored"), true);
            deflatedBomb().extractAllTo(pth.join(target, "deflated"), true);

            expect(oversized).to.eql([]);
            expect(fs.readFileSync(pth.join(target, "stored", "a")).equals(payload)).to.equal(true);
            expect(fs.readFileSync(pth.join(target, "deflated", "a")).equals(payload)).to.equal(true);
        });

        it("extractAllToAsync writes only the real bytes of over-declared entries", (done) => {
            storedBomb().extractAllToAsync(pth.join(target, "stored"), true, false, (err) => {
                if (err) return done(err);
                deflatedBomb().extractAllToAsync(pth.join(target, "deflated"), true, false, (err2) => {
                    if (err2) return done(err2);
                    try {
                        expect(oversized).to.eql([]);
                        expect(fs.readFileSync(pth.join(target, "stored", "a")).equals(payload)).to.equal(true);
                        expect(fs.readFileSync(pth.join(target, "deflated", "a")).equals(payload)).to.equal(true);
                        done();
                    } catch (e) {
                        done(e);
                    }
                });
            });
        });
    });
});
