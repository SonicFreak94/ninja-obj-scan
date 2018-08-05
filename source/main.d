import std.algorithm;
import std.array;
import std.bitmanip;
import std.conv;
import std.getopt;
import std.stdio;

const NJD_EVAL_MASK_LE = 0x3ff;
const NJD_EVAL_MASK_BE = swapEndian(NJD_EVAL_MASK_LE);

const STD_MODEL_DC = 0x28;
const STD_MODEL_EX = STD_MODEL_DC + 4;
const CNK_MODEL_DC = 0x18;
const CNK_MODEL_EX = CNK_MODEL_DC + 4;

uint binaryKey = 0x400000;
bool bigEndian = false;
size_t startOffset;

struct NJS_OBJECT
{
	uint evalflags;
	uint model;
	float[3] pos;
	int[3] ang;
	float[3] scl;
	uint child;
	uint sibling;

	void read(ubyte[] buffer)
	{
		auto buff = buffer.dup;

		evalflags = bigEndian
			? buff.read!(uint, Endian.bigEndian)()
			: buff.read!(uint, Endian.littleEndian)();

		model = bigEndian
			? buff.read!(uint, Endian.bigEndian)()
			: buff.read!(uint, Endian.littleEndian)();

		pos[0] = bigEndian
			? buff.read!(float, Endian.bigEndian)()
			: buff.read!(float, Endian.littleEndian)();

		pos[1] = bigEndian
			? buff.read!(float, Endian.bigEndian)()
			: buff.read!(float, Endian.littleEndian)();

		pos[2] = bigEndian
			? buff.read!(float, Endian.bigEndian)()
			: buff.read!(float, Endian.littleEndian)();

		ang[0] = bigEndian
			? buff.read!(int, Endian.bigEndian)()
			: buff.read!(int, Endian.littleEndian)();

		ang[1] = bigEndian
			? buff.read!(int, Endian.bigEndian)()
			: buff.read!(int, Endian.littleEndian)();

		ang[2] = bigEndian
			? buff.read!(int, Endian.bigEndian)()
			: buff.read!(int, Endian.littleEndian)();

		scl[0] = bigEndian
			? buff.read!(float, Endian.bigEndian)()
			: buff.read!(float, Endian.littleEndian)();

		scl[1] = bigEndian
			? buff.read!(float, Endian.bigEndian)()
			: buff.read!(float, Endian.littleEndian)();

		scl[2] = bigEndian
			? buff.read!(float, Endian.bigEndian)()
			: buff.read!(float, Endian.littleEndian)();

		child = bigEndian
			? buff.read!(uint, Endian.bigEndian)()
			: buff.read!(uint, Endian.littleEndian)();

		sibling = bigEndian
			? buff.read!(uint, Endian.bigEndian)()
			: buff.read!(uint, Endian.littleEndian)();
	}
}

void main(string[] args)
{
	try
	{
		auto r = getopt(args,
				"k|key", "The key for this binary. (0x400000 by default)", &binaryKey,
				"b|big-endian", "The binary is big endian. (false by default)", &bigEndian,
				"o|offset", "Start searching from the given offset", &startOffset);

		if (r.helpWanted || args.length == 1)
		{
			defaultGetoptPrinter("Scans binaries for NJS_OBJECT instances.", r.options);
			return;
		}
	}
	catch (Exception ex)
	{
		stderr.writeln(ex.msg);
		stderr.writeln("For usage information, use --help.");
		return;
	}

	// assuming 32-bit
	ubyte[4] buffer;
	ubyte[NJS_OBJECT.sizeof] obj_buffer;

	foreach (string path; args[1 .. $])
	{
		auto file = File(path, "rb");

		if (!file.isOpen)
		{
			stderr.writeln("Unable to open file: ", path);
			continue;
		}

		stdout.writeln("Checking file: ", path);

		if (startOffset)
		{
			file.seek(startOffset);
		}

		while (!file.eof)
		{
			auto slice = file.rawRead(buffer);
			if (slice.length < buffer.length)
			{
				break;
			}

			const offset = bigEndian
				? slice.peek!(uint, Endian.bigEndian)()
				: slice.peek!(uint, Endian.littleEndian)();

			if (offset < binaryKey)
			{
				file.seek(-3, SEEK_CUR);
				continue;
			}

			bool check_flags()
			{
				auto pos = file.tell();

				file.seek(-8, SEEK_CUR);
				auto s = file.rawRead(obj_buffer);
				file.seek(pos);

				if (s.length < obj_buffer.length)
				{
					return false;
				}

				NJS_OBJECT obj = {};
				obj.read(s);

				const mask = bigEndian ? NJD_EVAL_MASK_BE : NJD_EVAL_MASK_LE;

				if (obj.child != 0 && obj.child < binaryKey)
				{
					return false;
				}

				if (obj.sibling != 0 && obj.sibling < binaryKey)
				{
					return false;
				}

				return (obj.evalflags & ~mask) == 0;
			}

			const size_t object_offset = cast(size_t)(file.tell() - buffer.length - uint.sizeof);
			const size_t file_offset = offset - binaryKey;

			if (file_offset == object_offset - STD_MODEL_DC)
			{
				if (check_flags())
				{
					stdout.writefln("STD SADC FILE/MEMORY: %08X / %08X", object_offset, object_offset + binaryKey);
					file.seek(object_offset + 0x34 + 4); // + 4 to skip the NJD_EVAL flags, if any.
				}
			}
			else if (file_offset == object_offset - STD_MODEL_EX)
			{
				if (check_flags())
				{
					stdout.writefln("STD SADX FILE/MEMORY: %08X / %08X", object_offset, object_offset + binaryKey);
					file.seek(object_offset + 0x34 + 4); // + 4 to skip the NJD_EVAL flags, if any.
				}
			}
			else if (file_offset == object_offset - CNK_MODEL_DC)
			{
				if (check_flags())
				{
					stdout.writefln("CNK SADC FILE/MEMORY: %08X / %08X", object_offset, object_offset + binaryKey);
					file.seek(object_offset + 0x34 + 4); // + 4 to skip the NJD_EVAL flags, if any.
				}
			}
			else if (file_offset == object_offset - CNK_MODEL_EX)
			{
				if (check_flags())
				{
					stdout.writefln("CNK SADX FILE/MEMORY: %08X / %08X", object_offset, object_offset + binaryKey);
					file.seek(object_offset + 0x34 + 4); // + 4 to skip the NJD_EVAL flags, if any.
				}
			}
			else
			{
				file.seek(-3, SEEK_CUR);
			}
		}
	}
}
