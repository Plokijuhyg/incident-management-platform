using IncidentPlatform.Api.Authentication;
using Xunit;

namespace IncidentPlatform.Tests;

public class PasswordHasherTests
{
    private readonly IPasswordHasher _hasher = new PasswordHasher();

    [Fact]
    public void Hash_ProducesADifferentStringThanTheInput()
    {
        var hash = _hasher.Hash("CorrectHorseBatteryStaple");

        Assert.NotEqual("CorrectHorseBatteryStaple", hash);
        Assert.NotEmpty(hash);
    }

    [Fact]
    public void Hash_CalledTwiceOnTheSamePassword_ProducesDifferentHashes()
    {
        // This is the property that actually proves per-password salting is
        // happening — if two hashes of the same input were identical, an
        // attacker could spot two users sharing a password by comparing
        // hash values directly, which defeats the point of salting.
        var hash1 = _hasher.Hash("CorrectHorseBatteryStaple");
        var hash2 = _hasher.Hash("CorrectHorseBatteryStaple");

        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void Verify_WithTheCorrectPassword_ReturnsTrue()
    {
        var hash = _hasher.Hash("CorrectHorseBatteryStaple");

        var result = _hasher.Verify(hash, "CorrectHorseBatteryStaple");

        Assert.True(result);
    }

    [Fact]
    public void Verify_WithTheWrongPassword_ReturnsFalse()
    {
        var hash = _hasher.Hash("CorrectHorseBatteryStaple");

        var result = _hasher.Verify(hash, "WrongPassword");

        Assert.False(result);
    }

    [Fact]
    public void Hash_FitsWithinTheDatabaseColumnSize()
    {
        // database-design.md §4.1 specifies PasswordHash varchar(255).
        // This test exists so that if Identity's hash format ever grows in
        // a future .NET version, we find out here — in a fast unit test —
        // rather than via a truncated-hash bug in production.
        var hash = _hasher.Hash("CorrectHorseBatteryStaple");

        Assert.True(hash.Length <= 255, $"Hash length {hash.Length} exceeds the varchar(255) column size.");
    }
}
