using System.Security.Cryptography;

namespace SecurityDriven.Tests
{
	[TestClass]
	public class FastXorTests
	{
		[ThreadStatic] static byte[]? _dest, _left, _right;
		const int MAX_DATA_LENGTH = 32 * 1024;
		const int ITERATIONS = 20_000;
		const int UNALIGNED_MAX = 32;

		public static void InitData(int length)
		{
			_dest ??= new byte[MAX_DATA_LENGTH];
			_left ??= new byte[MAX_DATA_LENGTH];
			_right ??= new byte[MAX_DATA_LENGTH];

			_dest.AsSpan().Clear();
			RandomNumberGenerator.Fill(_left.AsSpan(0, length));
			RandomNumberGenerator.Fill(_right.AsSpan(0, length));
		}

		[TestMethod]
		public void Xor_dest_left_right()
		{
			for (int i = 0; i < ITERATIONS; ++i)
			{
				int unalignedStart = Random.Shared.Next(UNALIGNED_MAX);
				int length = Random.Shared.Next(minValue: 0, maxValue: MAX_DATA_LENGTH - unalignedStart + 1);

				InitData(length);

				var destSpan = _dest.AsSpan(unalignedStart, length);
				var leftSpan = _left.AsSpan(unalignedStart, length);
				var rightSpan = _right.AsSpan(unalignedStart, length);

				Correct.Xor(destSpan, leftSpan, rightSpan);
				string correctMAC = Correct.MAC(destSpan);

				destSpan.Clear();
				FastXor.Xor(destSpan, leftSpan, rightSpan);
				string testMAC = Correct.MAC(destSpan);
				Assert.IsTrue(correctMAC == testMAC);
			}//for
		}//Xor_dest_left_right()

		[TestMethod]
		public void Xor_dest_left()
		{
			for (int i = 0; i < ITERATIONS; ++i)
			{
				int unalignedStart = Random.Shared.Next(UNALIGNED_MAX);
				int length = Random.Shared.Next(minValue: 0, maxValue: MAX_DATA_LENGTH - unalignedStart + 1);

				InitData(length);

				var destSpan = _dest.AsSpan(unalignedStart, length);
				var leftSpan = _left.AsSpan(unalignedStart, length);
				var rightSpan = _right.AsSpan(unalignedStart, length);

				leftSpan.CopyTo(destSpan); // store copy of leftSpan into destSpan
				Correct.Xor(dest: leftSpan, left: rightSpan); // xor rightSpan into leftSpan
				string correctMAC = Correct.MAC(leftSpan);

				destSpan.CopyTo(leftSpan); // restore leftSpan to its initial random data
				FastXor.Xor(dest: leftSpan, left: rightSpan); // xor rightSpan into leftSpan again
				string testMAC = Correct.MAC(leftSpan);
				Assert.IsTrue(correctMAC == testMAC);
			}//for
		}//Xor_dest_left_right()

		[TestMethod]
		public void Xor_EdgeCases()
		{
			FastXor.Xor(null, null);
			FastXor.Xor(null, null, null);

			InitData(0);
			Console.WriteLine(Assert.ThrowsException<ArgumentOutOfRangeException>(() => FastXor.Xor(_dest.AsSpan(1), _left)));

			Console.WriteLine(Assert.ThrowsException<ArgumentOutOfRangeException>(() => FastXor.Xor(_dest.AsSpan(1), _left, _right)));
			Console.WriteLine(Assert.ThrowsException<ArgumentOutOfRangeException>(() => FastXor.Xor(_dest, _left.AsSpan(1), _right)));
			Console.WriteLine(Assert.ThrowsException<ArgumentOutOfRangeException>(() => FastXor.Xor(_dest, _left, _right.AsSpan(1))));
		}//Xor_EdgeCases()

		[TestMethod]
		public void Xor_Overlap()
		{
			static bool SpanAll(ReadOnlySpan<byte> span, Predicate<byte> condition)
			{
				for (int i = 0; i < span.Length; ++i)
					if (!condition(span[i]))
						return false;

				return true;
			}//SpanAll()

			for (int i = 0; i < ITERATIONS; ++i)
			{
				int length = Random.Shared.Next(minValue: MAX_DATA_LENGTH / 2, maxValue: MAX_DATA_LENGTH + 1);
				InitData(length);

				var destSpan = _dest.AsSpan(0, length);
				var leftSpan = _left.AsSpan(0, length);
				var rightSpan = _right.AsSpan(0, length);

				Assert.IsFalse(SpanAll(leftSpan, static b => b == 0));
				FastXor.Xor(dest: leftSpan, left: leftSpan);
				Assert.IsTrue(SpanAll(leftSpan, static b => b == 0));

				InitData(length);
				Assert.IsFalse(SpanAll(leftSpan, static b => b == 0));
				FastXor.Xor(dest: leftSpan, left: leftSpan, right: leftSpan);
				Assert.IsTrue(SpanAll(leftSpan, static b => b == 0));
			}//for
		}//Xor_Overlap()

		[TestMethod]
		public void Xor_BoundaryConditions()
		{
			InitData(MAX_DATA_LENGTH);

			var destSpan = _dest.AsSpan(0, MAX_DATA_LENGTH);
			var leftSpan = _left.AsSpan(0, MAX_DATA_LENGTH);
			var rightSpan = _right.AsSpan(0, MAX_DATA_LENGTH);

			Correct.Xor(destSpan, leftSpan, rightSpan);
			string correctMAC = Correct.MAC(destSpan);

			destSpan.Clear();
			FastXor.Xor(destSpan, leftSpan, rightSpan);
			string testMAC = Correct.MAC(destSpan);
			Assert.IsTrue(correctMAC == testMAC);

			InitData(0);
			destSpan = _dest.AsSpan(0, 0);
			leftSpan = _left.AsSpan(0, 0);
			rightSpan = _right.AsSpan(0, 0);

			Correct.Xor(destSpan, leftSpan, rightSpan);
			correctMAC = Correct.MAC(destSpan);

			destSpan.Clear();
			FastXor.Xor(destSpan, leftSpan, rightSpan);
			testMAC = Correct.MAC(destSpan);
			Assert.IsTrue(correctMAC == testMAC);
		}

		[TestMethod]
		public void Xor_SingleByteLength()
		{
			InitData(1);

			var destSpan = _dest.AsSpan(0, 1);
			var leftSpan = _left.AsSpan(0, 1);
			var rightSpan = _right.AsSpan(0, 1);

			Correct.Xor(destSpan, leftSpan, rightSpan);
			string correctMAC = Correct.MAC(destSpan);

			destSpan.Clear();
			FastXor.Xor(destSpan, leftSpan, rightSpan);
			string testMAC = Correct.MAC(destSpan);
			Assert.IsTrue(correctMAC == testMAC);
		}

		[TestMethod]
		public void Xor_LargeDataSets()
		{
			const int LARGE_DATA_LENGTH = 128 * 1024; // 128 KB
			_dest = new byte[LARGE_DATA_LENGTH];
			_left = new byte[LARGE_DATA_LENGTH];
			_right = new byte[LARGE_DATA_LENGTH];

			InitData(LARGE_DATA_LENGTH);

			var destSpan = _dest.AsSpan(0, LARGE_DATA_LENGTH);
			var leftSpan = _left.AsSpan(0, LARGE_DATA_LENGTH);
			var rightSpan = _right.AsSpan(0, LARGE_DATA_LENGTH);

			Correct.Xor(destSpan, leftSpan, rightSpan);
			string correctMAC = Correct.MAC(destSpan);

			destSpan.Clear();
			FastXor.Xor(destSpan, leftSpan, rightSpan);
			string testMAC = Correct.MAC(destSpan);
			Assert.IsTrue(correctMAC == testMAC);
		}
	}//class FastXorTests

	internal static class Correct
	{
		public static void Xor(Span<byte> dest, ReadOnlySpan<byte> left)
		{
			if (dest.Length != left.Length)
				throw new ArgumentOutOfRangeException(message: nameof(dest) + ".Length != " + nameof(left) + ".length", null);

			for (int i = 0; i < dest.Length; ++i) dest[i] ^= left[i];
		}//Xor(dest, left)

		public static void Xor(Span<byte> dest, ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
		{
			if (dest.Length != left.Length || dest.Length != right.Length)
				throw new ArgumentOutOfRangeException(message: nameof(dest) + "," + nameof(left) + "," + nameof(right) + " have different lengths.", null);

			for (int i = 0; i < dest.Length; ++i) dest[i] = (byte)(left[i] ^ right[i]);
		}//Xor(dest, left, right)

		public static string MAC(ReadOnlySpan<byte> data) => Convert.ToHexString(SHA384.HashData(data));
	}//class Correct
}//ns