package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import hp3.adapter.Hp3Extension;

public class Extension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("HTTP/3 Adapter");

        Hp3Extension adapter = Hp3Extension.install(api);
        api.extension().registerUnloadingHandler(adapter::close);
        api.logging().logToOutput(
                "HTTP/3 Adapter loaded in mode: " + adapter.settings().mode().label());
    }
}
