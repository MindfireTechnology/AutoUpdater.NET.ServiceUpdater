using System.Xml;
using System.Xml.Serialization;
using AutoUpdaterDotNET;
using Shouldly;

namespace AutoUpdater.NET.Tests;

public class XmlSerializationTest
{

	static string XmlManifestExample = """
		<?xml version="1.0" encoding="utf-8" ?>
		<item>
			<version>2.0.0.0</version>
			<url>Update.zip</url>
			<mandatory mode="2">true</mandatory>
			<service>WindowsServiceName</service>
		</item>
		""";

	[Fact]
	public void ServiceName()
	{
		var xmlSerializer = new XmlSerializer(typeof(UpdateInfoEventArgs));
		var xmlTextReader = new XmlTextReader(new StringReader(XmlManifestExample)) { XmlResolver = null };
		var args = xmlSerializer.Deserialize(xmlTextReader) as UpdateInfoEventArgs;

		args.ShouldNotBeNull();
		args.SerivceName.ShouldBe("WindowsServiceName");
		args.CurrentVersion.ShouldBe("2.0.0.0");
		args.Mandatory.Value.ShouldBe(true);
		args.Mandatory.UpdateMode.ShouldBe(Mode.ForcedDownload);
	}
}
