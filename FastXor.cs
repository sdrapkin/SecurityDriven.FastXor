using System;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace SecurityDriven
{
	public static class FastXor
	{
		[DoesNotReturn]
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ThrowArgumentOutOfRange(string message) => throw new ArgumentOutOfRangeException(message: message, innerException: null);

		public static void Xor(Span<byte> dest, ReadOnlySpan<byte> left)
		{
			if (dest.Length != left.Length)
				ThrowArgumentOutOfRange(message: nameof(dest) + ".Length != " + nameof(left) + ".length");

			int i = 0, vectorLength = Vector<byte>.Count << 2;
			Span<byte> leftSpan = MemoryMarshal.CreateSpan(ref MemoryMarshal.GetReference(left), left.Length);

			for (int vectorLimit = dest.Length - vectorLength; i <= vectorLimit; i += vectorLength)
			{
				ref (Vector<byte>, Vector<byte>, Vector<byte>, Vector<byte>) reference = ref Unsafe.As<byte, (Vector<byte>, Vector<byte>, Vector<byte>, Vector<byte>)>(ref dest[i]);
				ref (Vector<byte>, Vector<byte>, Vector<byte>, Vector<byte>) leftVectors = ref Unsafe.As<byte, (Vector<byte>, Vector<byte>, Vector<byte>, Vector<byte>)>(ref leftSpan[i]);
				reference.Item4 ^= leftVectors.Item4;
				reference.Item3 ^= leftVectors.Item3;
				reference.Item2 ^= leftVectors.Item2;
				reference.Item1 ^= leftVectors.Item1;
			}

			vectorLength >>= 1;
			for (int vectorLimit = dest.Length - vectorLength; i <= vectorLimit; i += vectorLength)
			{
				ref (Vector<byte>, Vector<byte>) reference2 = ref Unsafe.As<byte, (Vector<byte>, Vector<byte>)>(ref dest[i]);
				ref (Vector<byte>, Vector<byte>) leftVectors2 = ref Unsafe.As<byte, (Vector<byte>, Vector<byte>)>(ref leftSpan[i]);
				reference2.Item2 ^= leftVectors2.Item2;
				reference2.Item1 ^= leftVectors2.Item1;
			}

			vectorLength >>= 1;
			for (int vectorLimit = dest.Length - vectorLength; i <= vectorLimit; i += vectorLength)
			{
				Unsafe.As<byte, Vector<byte>>(ref dest[i]) ^= Unsafe.As<byte, Vector<byte>>(ref leftSpan[i]);
			}

			for (int vectorLimit = dest.Length - sizeof(long); i <= vectorLimit; i += sizeof(long))
			{
				Unsafe.As<byte, long>(ref dest[i]) ^= Unsafe.As<byte, long>(ref leftSpan[i]);
			}

			for (; i < dest.Length; i++)
			{
				dest[i] ^= leftSpan[i];
			}
		}// Xor(dest, left)

		public static void Xor(Span<byte> dest, ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
		{
			if ((dest.Length != left.Length) || (dest.Length != right.Length))
				ThrowArgumentOutOfRange(message: nameof(dest) + "," + nameof(left) + "," + nameof(right) + " have different lengths.");

			int i = 0, vectorLength = Vector<byte>.Count << 2;
			Span<byte> leftSpan = MemoryMarshal.CreateSpan(ref MemoryMarshal.GetReference(left), left.Length);
			Span<byte> rightSpan = MemoryMarshal.CreateSpan(ref MemoryMarshal.GetReference(right), right.Length);

			for (int vectorLimit = dest.Length - vectorLength; i <= vectorLimit; i += vectorLength)
			{
				ref (Vector<byte>, Vector<byte>, Vector<byte>, Vector<byte>) destVectors = ref Unsafe.As<byte, (Vector<byte>, Vector<byte>, Vector<byte>, Vector<byte>)>(ref dest[i]);
				ref (Vector<byte>, Vector<byte>, Vector<byte>, Vector<byte>) leftVectors = ref Unsafe.As<byte, (Vector<byte>, Vector<byte>, Vector<byte>, Vector<byte>)>(ref leftSpan[i]);
				ref (Vector<byte>, Vector<byte>, Vector<byte>, Vector<byte>) rightVectors = ref Unsafe.As<byte, (Vector<byte>, Vector<byte>, Vector<byte>, Vector<byte>)>(ref rightSpan[i]);
				destVectors.Item4 = leftVectors.Item4 ^ rightVectors.Item4;
				destVectors.Item3 = leftVectors.Item3 ^ rightVectors.Item3;
				destVectors.Item2 = leftVectors.Item2 ^ rightVectors.Item2;
				destVectors.Item1 = leftVectors.Item1 ^ rightVectors.Item1;
			}

			vectorLength >>= 1;
			for (int vectorLimit = dest.Length - vectorLength; i <= vectorLimit; i += vectorLength)
			{
				ref (Vector<byte>, Vector<byte>) destVectors = ref Unsafe.As<byte, (Vector<byte>, Vector<byte>)>(ref dest[i]);
				ref (Vector<byte>, Vector<byte>) leftVectors = ref Unsafe.As<byte, (Vector<byte>, Vector<byte>)>(ref leftSpan[i]);
				ref (Vector<byte>, Vector<byte>) rightVectors = ref Unsafe.As<byte, (Vector<byte>, Vector<byte>)>(ref rightSpan[i]);
				destVectors.Item2 = leftVectors.Item2 ^ rightVectors.Item2;
				destVectors.Item1 = leftVectors.Item1 ^ rightVectors.Item1;
			}

			vectorLength >>= 1;
			for (int vectorLimit = dest.Length - vectorLength; i <= vectorLimit; i += vectorLength)
			{
				Unsafe.As<byte, Vector<byte>>(ref dest[i]) ^= Unsafe.As<byte, Vector<byte>>(ref leftSpan[i]);
			}

			for (int vectorLimit = dest.Length - sizeof(long); i <= vectorLimit; i += sizeof(long))
			{
				Unsafe.As<byte, long>(ref dest[i]) ^= Unsafe.As<byte, long>(ref leftSpan[i]);
			}

			for (; i < dest.Length; i++)
			{
				dest[i] ^= leftSpan[i];
			}
		}// Xor(dest, left, right)
	}//class FastXor
}//ns