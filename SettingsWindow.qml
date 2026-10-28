// Omapager - the full preferences window.
//
// The panel's own settings page is 380 logical pixels wide and anchored to the
// bar, which is right for three toggles and wrong for a provider list, a base
// URL, a model name, a key field and a test button. Those need room, a keyboard
// focus that does not depend on a bar anchor, and the ability to stay open for
// longer than a click. So they live in their own floating window, opened from
// the same cog the panel already has.
//
// The window is also where the panel's small toggles move to, eventually; for
// now it covers only what does not fit there, so there is one home per setting
// and no setting with two controls.
//
// The API key never passes through this window as data: it is written into the
// desktop keyring by bin/omapager-secret, and read back only as "set" or "not
// set". Nothing here can display it.
import QtQuick
import QtQuick.Controls
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

FloatingWindow {
  id: window
  title: "Omapager preferences"
  minimumSize: Qt.size(520, 420)
  maximumSize: Qt.size(900, 900)
  implicitWidth: 620
  implicitHeight: 720
  color: Color.background
  // The daemon and the widget that owns the settings entry. The widget is the
  // only object handed the plugin's shell.json entry, so every write goes back
  // through it and every read comes from it.
  property var pager: null
  // Theme roles, read the same way the panel reads them. A window is not a
  // surface inside the bar, so it cannot borrow the bar's colours; these are
  // the theme's own foreground/background, which is what every other
  // full-size Omarchy window uses. The names avoid `foreground` and
  // `background`: a FloatingWindow already has both, and shadowing them
  // produced a binding loop rather than a compile error.
  readonly property color ink: Color.foreground
  readonly property color surface: Color.background
  readonly property color dimInk: Qt.darker(ink, 1.4)
  readonly property var service: pager ? pager.service : null
  readonly property bool ready: pager !== null

  // Local working copy. Nothing is persisted until a control is used, and the
  // values here are the ones the widget reports as configured, so opening the
  // window never rewrites a setting the user did not touch.
  readonly property string provider: pager ? pager.configuredLlmProvider : "off"
  readonly property string customUrl: pager ? pager.configuredLlmBaseUrl : ""
  readonly property string model: pager ? pager.configuredLlmModel : ""
  readonly property bool dedupe: pager ? pager.configuredLlmDedupe : true
  readonly property string dedupeModel: pager ? pager.configuredLlmDedupeModel : ""
  readonly property string dedupeApi: pager ? pager.configuredLlmDedupeApi : "chat"
  readonly property bool intent: pager ? pager.configuredLlmIntent : true

  readonly property var providerOptions: [
    { value: "off", label: "Off - no model is contacted" },
    { value: "ollama", label: "Ollama (this machine)" },
    { value: "lmstudio", label: "LM Studio (this machine)" },
    { value: "llamacpp", label: "llama.cpp server (this machine)" },
    { value: "openrouter", label: "OpenRouter" },
    { value: "openai", label: "OpenAI" },
    { value: "deepseek", label: "DeepSeek" },
    { value: "custom", label: "Custom OpenAI-compatible endpoint" }
  ]
  readonly property bool llmOn: provider !== "off"
  readonly property bool remote: ["openrouter", "openai", "deepseek", "custom"].indexOf(provider) >= 0
  readonly property bool needsUrl: provider === "custom"

  // Key state, as the keyring reports it. "unknown" until the probe answers,
  // so a Delete button never appears for a key that is not there.
  property string keyState: "unknown"     // unknown | absent | stored
  property string keyNotice: ""
  property string llmStatus: ""
  property bool testing: false
  property bool listing: false

  readonly property string secretBin: Qt.resolvedUrl("bin/omapager-run-secret").toString().replace(/^file:\/\//, "")
  readonly property string llmBin: Qt.resolvedUrl("bin/omapager-run-llm").toString().replace(/^file:\/\//, "")

  function refreshKeyState() {
    secretStatus.running = false
    secretStatus.running = true
  }

  function saveKey(value) {
    if (!value) return
    // The helper reads the key on stdin until EOF, so the pipe has to be closed
    // after the write. Leaving it open is not a hang the user can see: the
    // wrapper's watchdog kills the helper 45 seconds later, and the only
    // symptom is that nothing was ever stored. Same shape as Store._pump.
    keyNotice = ""
    keyWrite.command = [secretBin, "set"]
    keyWrite.stdinEnabled = true
    keyWrite.running = true
    keyWrite.write(String(value))
    keyWrite.stdinEnabled = false
  }

  function forgetKey() {
    keyClear.running = false
    keyClear.running = true
  }

  function testConnection() {
    llmStatus = ""
    testing = true
    llmStatusProc.running = false
    llmStatusProc.command = [llmBin, "status", provider, customUrl || "", model || "",
                             dedupeModel || "", dedupeApi || "chat"]
    llmStatusProc.running = true
  }

  // What to say about a provider's answer. Each failure gets its own sentence:
  // "no answer" for all four was the reason a missing key and a blocked network
  // looked like the same problem.
  function describe(status) {
    if (!status) return "No answer from the provider."
    if (status.reachable) {
      var base = "Connected to " + status.baseUrl
      // A model id the provider lists but refuses is otherwise invisible: the
      // duplicate simply never merges and nothing says why.
      if (status.dedupe && status.dedupe.ok !== true)
        base += " - but " + status.dedupe.model + " was refused (" + status.dedupe.detail + ")"
      return base
    }
    var base = status.baseUrl || "the provider"
    switch (status.detail) {
    case "no provider": return "Choose a provider first."
    case "no key stored": return "No API key is stored for this provider."
    case "answered, but rejected the request":
      return base + " answered but rejected the request. Check the key and the model name."
    case "could not be reached":
      return "Could not reach " + base + ". Check the address and the network."
    default:
      return status.detail ? String(status.detail) : ("No answer from " + base)
    }
  }

  function loadModels() {
    listing = true
    modelList.running = false
    modelList.command = [llmBin, "models", provider, customUrl || "", model || ""]
    modelList.running = true
  }

  Process {
    id: secretStatus
    running: false
    command: [secretBin, "status"]
    stdout: StdioCollector {
      onStreamFinished: {
        var parsed = null
        try { parsed = JSON.parse(text) } catch (e) { parsed = null }
        window.keyState = parsed && parsed.available === true && parsed.stored === true
                        ? "stored" : "absent"
      }
    }
  }

  Process {
    id: keyWrite
    running: false
    stdout: StdioCollector { onStreamFinished: window.keyNotice = "" }
    onExited: function(code, status) {
      window.keyNotice = code === 0
        ? "Key saved in the desktop keyring."
        : "Could not save the key: the secret service refused it, or is not running."
      window.refreshKeyState()
    }
  }

  Process {
    id: keyClear
    running: false
    command: [secretBin, "clear"]
    onExited: { window.keyState = "absent"; window.keyNotice = "Key removed." }
  }

  Process {
    id: llmStatusProc
    running: false
    stdout: StdioCollector {
      onStreamFinished: {
        window.testing = false
        var status = null
        try { status = JSON.parse(text) } catch (e) { status = null }
        window.llmStatus = window.describe(status)
      }
    }
  }

  Process {
    id: modelList
    running: false
    property var names: []
    stdout: StdioCollector {
      onStreamFinished: {
        window.listing = false
        modelList.names = text.split("\n").filter(function (line) { return line.length > 0 })
      }
    }
  }

  // ---------------------------------------------------------------- layout
  Rectangle {
    anchors.fill: parent
    color: window.surface

    Flickable {
      anchors.fill: parent
      anchors.margins: Style.spacing.huge
      contentWidth: width
      contentHeight: column.implicitHeight
      clip: true
      boundsBehavior: Flickable.StopAtBounds
      ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

      Column {
        id: column
        width: parent.width
        spacing: Style.spacing.huge

        Text {
          width: parent.width
          text: "Notification model"
          color: window.ink
          font.family: Style.font.family
          font.pixelSize: Style.font.title
          font.bold: true
        }

        Text {
          width: parent.width
          text: "Omapager can ask a model to spot duplicates and suggest buttons. "
              + "It is off until you choose a provider here. Nothing is sent while it is off, "
              + "and the key is kept in the desktop keyring, not in shell.json."
          color: window.dimInk
          font.family: Style.font.family
          font.pixelSize: Style.font.bodySmall
          wrapMode: Text.WordWrap
        }

        Picker {
          id: providerPicker
          width: parent.width
          label: "Provider"
          value: window.provider
          options: window.providerOptions
          foreground: window.ink
          fontFamily: Style.font.family
          onPicked: function (value) { pager.persistSettings({ llmProvider: value }) }
        }

        Column {
          width: parent.width
          spacing: Style.spacing.lg
          visible: window.needsUrl

          TextField {
            width: parent.width
            text: window.customUrl
            placeholderText: "https://host/v1"
            foreground: window.ink
            font.family: Style.font.family
            onEditingFinished: pager.persistSettings({ llmBaseUrl: text })
          }
          Text {
            width: parent.width
            text: "Must end in /v1. Plain http is accepted only for 127.0.0.1 or ::1."
            color: window.dimInk
            font.family: Style.font.family
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
          }
        }

        Column {
          width: parent.width
          spacing: Style.spacing.lg
          visible: window.llmOn

          TextField {
            id: modelField
            width: parent.width
            text: window.model
            placeholderText: "Model name, or leave empty for the provider default"
            foreground: window.ink
            font.family: Style.font.family
            onEditingFinished: pager.persistSettings({ llmModel: text })
          }

          Row {
            spacing: Style.spacing.controlGap
            Button {
              text: window.listing ? "Listing..." : "List models"
              enabled: !window.listing
              onClicked: window.loadModels()
            }
            Button {
              text: window.testing ? "Testing..." : "Test connection"
              enabled: !window.testing
              onClicked: window.testConnection()
            }
          }

          // Populated by "List models"; a plain row of choices rather than a
          // dropdown, because the list can be long and is read, not searched.
          Column {
            width: parent.width
            spacing: Style.space(4)
            Repeater {
              model: modelList.names.slice(0, 12)
              Button {
                required property var modelData
                width: parent.width
                text: String(modelData)
                onClicked: {
                  modelField.text = String(modelData)
                  pager.persistSettings({ llmModel: String(modelData) })
                }
              }
            }
          }

          Text {
            width: parent.width
            visible: window.llmStatus !== ""
            text: window.llmStatus
            color: window.dimInk
            font.family: Style.font.family
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
          }
        }

        PanelSeparator { foreground: window.ink }

        Column {
          width: parent.width
          spacing: Style.spacing.lg
          visible: window.remote

          Text {
            width: parent.width
            text: "API key"
            color: window.ink
            font.family: Style.font.family
            font.pixelSize: Style.font.body
          }

          Row {
            width: parent.width
            spacing: Style.spacing.controlGap

            TextField {
              id: keyField
              width: parent.width - keyButtons.width - parent.spacing
              password: true
              placeholderText: window.keyState === "stored"
                ? "A key is stored. Type a new one to replace it."
                : "Paste the provider's API key"
              foreground: window.ink
              font.family: Style.font.family
            }

            Row {
              id: keyButtons
              spacing: Style.spacing.controlGap

              Button {
                text: "Save"
                enabled: keyField.text.length > 0
                onClicked: {
                  window.saveKey(keyField.text)
                  keyField.text = ""
                }
              }
              Button {
                text: "Delete"
                visible: window.keyState === "stored"
                onClicked: window.forgetKey()
              }
            }
          }

          Text {
            width: parent.width
            text: window.keyState === "stored"
              ? "Stored in the desktop keyring."
              : "No key stored."
            color: window.dimInk
            font.family: Style.font.family
            font.pixelSize: Style.font.bodySmall
          }

          Text {
            width: parent.width
            visible: window.keyNotice !== ""
            text: window.keyNotice
            color: window.dimInk
            font.family: Style.font.family
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
          }
        }

        PanelSeparator { foreground: window.ink }

        Column {
          width: parent.width
          spacing: Style.spacing.lg

          Text {
            width: parent.width
            text: "What the model may do"
            color: window.ink
            font.family: Style.font.family
            font.pixelSize: Style.font.body
          }

          Row {
            width: parent.width
            spacing: Style.spacing.controlGap
            Text {
              width: parent.width - dedupeSwitch.width - parent.spacing
              anchors.verticalCenter: parent.verticalCenter
              text: "Hide duplicated messages from another source"
              color: window.ink
              font.family: Style.font.family
              font.pixelSize: Style.font.body
              wrapMode: Text.WordWrap
            }
            ToggleSwitch {
              id: dedupeSwitch
              anchors.verticalCenter: parent.verticalCenter
              checked: window.dedupe
              foreground: window.ink
              onToggled: pager.persistSettings({ llmDedupe: !window.dedupe })
            }
          }

          Text {
            width: parent.width
            text: "Show one card when the same message arrives from two sources. "
                + "Identical text is merged either way; this also merges wording "
                + "that differs but means the same."
            color: window.dimInk
            font.family: Style.font.family
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
          }

          // A cheaper second model for the duplicate question alone. Offered
          // both ways: a list from the provider so the common case is a click,
          // and a text field for a name the list does not have.
          Column {
            width: parent.width
            spacing: Style.spacing.lg
            visible: window.dedupe

            Picker {
              id: dedupeModelPicker
              width: parent.width
              label: "Model for duplicate checks"
              value: window.dedupeModel
              options: [{ value: "", label: "Same model as above" }].concat(
                modelList.names.map(function (name) { return { value: name, label: name } }))
              foreground: window.ink
              fontFamily: Style.font.family
              onPicked: function (value) { pager.persistSettings({ llmDedupeModel: value }) }
            }

            TextField {
              id: dedupeModelField
              width: parent.width
              text: window.dedupeModel
              placeholderText: "Or type a model name, empty for the model above"
              foreground: window.ink
              font.family: Style.font.family
              onEditingFinished: pager.persistSettings({ llmDedupeModel: text })
            }

            Picker {
              id: dedupeApiPicker
              width: parent.width
              label: "How to ask"
              value: window.dedupeApi
              options: [
                { value: "chat", label: "Chat model - reads a JSON reply" },
                { value: "systemone", label: "System One model - one yes/no, a probability" }
              ]
              foreground: window.ink
              fontFamily: Style.font.family
              onPicked: function (value) { pager.persistSettings({ llmDedupeApi: value }) }
            }

            Text {
              width: parent.width
              text: window.dedupeApi === "systemone"
                ? "One question, one number, nothing to parse. A model like Jev "
                  + "(for example group/jev at Magpie) scores the pair from 0 to 1 and a "
                  + "card is merged above 0.7. This is the cheap path."
                : "Check only: two notifications, one boolean. A small or flash "
                  + "model is enough and costs less than the one used for buttons."
              color: window.dimInk
              font.family: Style.font.family
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }
          }

          Row {
            width: parent.width
            spacing: Style.spacing.controlGap
            Text {
              width: parent.width - intentSwitch.width - parent.spacing
              anchors.verticalCenter: parent.verticalCenter
              text: "Suggest buttons from the message"
              color: window.ink
              font.family: Style.font.family
              font.pixelSize: Style.font.body
              wrapMode: Text.WordWrap
            }
            ToggleSwitch {
              id: intentSwitch
              anchors.verticalCenter: parent.verticalCenter
              checked: window.intent
              foreground: window.ink
              onToggled: pager.persistSettings({ llmIntent: !window.intent })
            }
          }

          Text {
            width: parent.width
            text: "A suggested button must point at text the notification already "
                + "contains. The model cannot add a link, a path or a command."
            color: window.dimInk
            font.family: Style.font.family
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
          }
        }

        Row {
          width: parent.width
          spacing: Style.spacing.controlGap

          Button {
            text: "Display and panel settings"
            onClicked: {
              window.visible = false
              if (window.pager) window.pager.openSettings()
            }
          }

          Button {
            text: "Close"
            onClicked: window.visible = false
          }
        }
      }
    }
  }

  onVisibleChanged: {
    if (!visible) return
    keyField.text = ""
    keyNotice = ""
    llmStatus = ""
    refreshKeyState()
  }

  Component.onCompleted: refreshKeyState()
}
