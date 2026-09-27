"use strict";

const { expect } = require("chai");
const Zip = require("../adm-zip");
const Constants = require("../util").Constants;

describe("zip64", () => {
    it("writes and reads archives with more than 65535 entries", function () {
        this.timeout(10000);

        const entryCount = 0x10000;
        const zip = new Zip({ noSort: true });

        for (let i = 0; i < entryCount; i++) {
            zip.addFile(`file-${i}.txt`, "");
        }

        const buffer = zip.toBuffer();
        const readZip = new Zip(buffer);

        expect(readZip.getEntries()).to.have.lengthOf(entryCount);
    });

    it("writes the archive comment after the zip64 end records", function () {
        this.timeout(10000);

        const entryCount = 0x10000;
        const comment = "zip64 archive comment";
        const zip = new Zip({ noSort: true });

        for (let i = 0; i < entryCount; i++) {
            zip.addFile(`file-${i}.txt`, "");
        }
        zip.addZipComment(comment);

        const buffer = zip.toBuffer();
        const eocdOffset = buffer.length - comment.length - Constants.ENDHDR;

        expect(buffer.readUInt32LE(eocdOffset)).to.equal(Constants.ENDSIG);
        expect(buffer.readUInt16LE(eocdOffset + Constants.ENDCOM)).to.equal(comment.length);
        expect(buffer.readUInt32LE(eocdOffset - Constants.END64HDR)).to.equal(Constants.END64SIG);
        expect(buffer.readUInt32LE(eocdOffset - Constants.END64HDR - Constants.ZIP64HDR)).to.equal(Constants.ZIP64SIG);
        expect(buffer.slice(buffer.length - comment.length).toString()).to.equal(comment);

        expect(new Zip(buffer).getEntries()).to.have.lengthOf(entryCount);
    });

    it("keeps the archive comment intact when rewriting an archive with trailing data", () => {
        const zip = new Zip();
        zip.addFile("a.txt", "content");
        zip.addZipComment("abc");

        // bytes after the declared comment end up in the loaded comment buffer
        const withTrailingData = Buffer.concat([zip.toBuffer(), Buffer.alloc(40)]);
        const rewritten = new Zip(new Zip(withTrailingData).toBuffer());

        expect(rewritten.getZipComment()).to.equal("abc");
        expect(rewritten.readAsText("a.txt")).to.equal("content");
    });
});
