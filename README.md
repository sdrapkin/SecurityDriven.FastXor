# **FastXor** [![NuGet](https://img.shields.io/nuget/v/FastXor.svg)](https://www.nuget.org/packages/FastXor/)

### by [Stan Drapkin](https://github.com/sdrapkin/)

## Fast `Xor` for .NET
Uses SIMD acceleration for up to 32x speed-up.

---
### Methods:
```csharp
///Xor's left byte span into dest byte span.
public static void Xor(Span<byte> dest, ReadOnlySpan<byte> left)

///Xor's left and right byte spans into dest byte span.
public static void Xor(Span<byte> dest, ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
```