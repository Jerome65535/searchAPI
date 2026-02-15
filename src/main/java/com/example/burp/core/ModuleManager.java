package com.example.burp.core;

import burp.IHttpRequestResponse;

import java.util.ArrayList;
import java.util.List;

public class ModuleManager {
    private final List<Module> modules = new ArrayList<Module>();

    public void addModule(Module module) {
        modules.add(module);
    }

    public List<Module> getModules() {
        return modules;
    }

    public void processResponse(int toolFlag, IHttpRequestResponse messageInfo) {
        for (Module module : modules) {
            try {
                module.processResponse(toolFlag, messageInfo);
            } catch (Exception ignored) {
            }
        }
    }

    public void processManual(Module module, IHttpRequestResponse messageInfo) {
        if (module == null) {
            return;
        }
        try {
            module.processManual(messageInfo);
        } catch (Exception ignored) {
        }
    }
}
