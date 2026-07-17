using Dawa.Models;
using Xunit;

namespace Dawa.Tests;

public class JidTests
{
    [Fact]
    public void Parse_UserServer()
    {
        var j = JID.Parse("31612345678@s.whatsapp.net");
        Assert.Equal("31612345678", j.User);
        Assert.Equal("s.whatsapp.net", j.Server);
        Assert.Null(j.Device);
        Assert.True(j.IsUser);
    }

    [Fact]
    public void Parse_UserDeviceServer()
    {
        var j = JID.Parse("824767959274:96@lid");
        Assert.Equal("824767959274", j.User);
        Assert.Equal("96", j.Device);
        Assert.Equal("lid", j.Server);
    }

    [Fact]
    public void Parse_Group()
    {
        var j = JID.Parse("120363012345678901@g.us");
        Assert.True(j.IsGroup);
        Assert.Equal("g.us", j.Server);
    }

    [Fact]
    public void ToString_RoundTrips()
    {
        Assert.Equal("31612345678@s.whatsapp.net", JID.Parse("31612345678@s.whatsapp.net").ToString());
        Assert.Equal("824767959274:96@lid", JID.Parse("824767959274:96@lid").ToString());
    }

    [Fact]
    public void Parse_EmptyThrows()
    {
        Assert.Throws<System.ArgumentException>(() => JID.Parse("  "));
    }
}
