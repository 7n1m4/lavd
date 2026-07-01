// AnimaTab — native-messaging host bridge for AnimaSchedEXT
// Reports active tab's processId to /usr/local/bin/anima-tab-host.

const HOST = "anima_tab";

async function notifyActiveTab() {
    try {
        const tabs = await browser.tabs.query({active: true, currentWindow: true});
        if (!tabs.length) return;
        const tab = tabs[0];
        if (typeof tab.processId !== "number") return;
        await browser.runtime.sendNativeMessage(HOST, {pid: tab.processId});
    } catch (e) {
        // daemon not running or extension missing — silent
    }
}

// Tab activation events
browser.tabs.onActivated.addListener(i => notifyActiveTab());

// Tab replacement (SAB / swapped from background)
browser.tabs.onCreated.addListener(tab => {
    if (tab.active) notifyActiveTab();
});

// Load complete
browser.tabs.onUpdated.addListener((tabId, info) => {
    if (info.status !== "complete") return;
    browser.tabs.get(tabId).then(tab => {
        if (tab.active) notifyActiveTab();
    });
});

// Fire once at extension startup
notifyActiveTab();
