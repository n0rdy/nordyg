import SwiftUI

/// The command bar: one row. A monospaced field with the type and resolver as
/// inline tokens, the options button, and Run. The mode picker lives in the
/// window toolbar.
struct QueryBar: View {
    @EnvironmentObject var model: AppModel
    @State private var showCustom = false
    @FocusState private var nameFocused: Bool

    var body: some View {
        HStack(spacing: 10) {
            HStack(spacing: 0) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary).padding(.leading, 10).padding(.trailing, 6)
                TextField(placeholder, text: $model.name)
                    .textFieldStyle(.plain)
                    .font(.system(.title3, design: .monospaced))
                    .focused($nameFocused)
                    .onSubmit { model.run() }
                if !model.mode.takesDomain {
                    Token {
                        Picker("Type", selection: $model.type) {
                            // ALL fans out per type; times several resolvers it
                            // would explode, so it is a one-resolver choice.
                            ForEach(model.mode == .query && model.severalResolvers ? RecordTypes.all.filter { $0 != "ALL" } : RecordTypes.all, id: \.self) { Text($0).tag($0) }
                        }
                        .pickerStyle(.inline)
                    } label: {
                        Text(model.type).font(.system(.callout, design: .monospaced).weight(.bold)).foregroundStyle(TypeStyle.ink(model.type))
                    }
                }
                if model.mode == .query && model.severalResolvers {
                    CompareEndpointPicker(open: $model.showResolverChecklist, addResolver: { showCustom = true })
                } else if model.mode.usesResolver {
                    Token {
                        // First in the menu: the list below is long, and an
                        // option at its end goes unseen.
                        if model.mode == .query {
                            Button {
                                model.severalResolvers = true
                                // Open the checklist once the token has swapped in.
                                DispatchQueue.main.async { model.showResolverChecklist = true }
                            } label: {
                                Label("Several resolvers…", systemImage: "checklist")
                            }
                            Divider()
                        }
                        EndpointPickerItems(selection: $model.selected)
                        Divider()
                        Button("Add resolver…") { showCustom = true }
                        if !model.customEndpoints.isEmpty {
                            Menu("Remove custom resolver") {
                                ForEach(model.customEndpoints) { ep in Button(ep.title) { model.removeCustom(ep) } }
                            }
                        }
                    } label: {
                        Label(model.selected?.title ?? "resolver", systemImage: "server.rack").font(.callout).lineLimit(1)
                    }
                } else {
                    Text("root → authoritative").font(.callout).foregroundStyle(.secondary).padding(.horizontal, 10)
                }
            }
            .frame(height: 40)
            .background(RoundedRectangle(cornerRadius: 10).fill(Color(nsColor: .textBackgroundColor)))
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(nameFocused ? Color.accentColor.opacity(0.7) : Color.secondary.opacity(0.25), lineWidth: nameFocused ? 1.5 : 1))

            OptionsButton(options: $model.options, validate: $model.validate,
                          showsValidate: model.mode == .query || model.mode == .trace)

            if model.isRunning {
                // A plain button: red means "failed" in the results.
                // Run and Cancel share a size so the bar does not jump.
                Button { model.cancel() } label: { Label("Cancel", systemImage: "stop.fill").font(.title3).frame(minWidth: 84) }
                    .controlSize(.extraLarge)
            } else {
                // As tall as the field, with its text size.
                Button { model.run() } label: { Label("Run", systemImage: "play.fill").font(.title3.weight(.semibold)).frame(minWidth: 84) }
                    .keyboardShortcut(.defaultAction)
                    .disabled(!model.canRun)
                    .buttonStyle(.borderedProminent)
                    .controlSize(.extraLarge)
            }
        }
        .padding(12)
        .sheet(isPresented: $showCustom) { CustomEndpointSheet() }
        .sheet(item: Binding(get: { model.presets.first { $0.id == model.setupPreset } }, set: { model.setupPreset = $0?.id })) { p in
            PresetSetupSheet(preset: p)
        }
        .onAppear { nameFocused = true }
    }

    var placeholder: String {
        switch model.mode {
        case .email: return "mail domain"
        case .registry: return "registered domain"
        case .health: return "zone"
        default: return "name or IP address"
        }
    }
}

/// A menu styled as an inline token inside the command bar.
struct Token<Content: View, L: View>: View {
    @ViewBuilder var content: Content
    @ViewBuilder var label: L

    var body: some View {
        Menu { content } label: { label }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
            .tokenChrome()
    }
}

private extension View {
    /// The rounded tile a token sits in, with the gap to the next one.
    func tokenChrome() -> some View {
        padding(.horizontal, 8).padding(.vertical, 4)
            .background(Color.secondary.opacity(0.12))
            .clipShape(RoundedRectangle(cornerRadius: 6))
            .padding(.trailing, 6)
    }
}

/// The resolver menu: this Mac's resolvers, one submenu per provider (its
/// transports, then "More addresses"), and custom ones.
struct EndpointPickerItems: View {
    @EnvironmentObject var model: AppModel
    @Binding var selection: Endpoint?

    var body: some View {
        if !model.systemEndpoints.isEmpty {
            Section("This Mac") {
                Picker("", selection: $selection) {
                    ForEach(model.systemEndpoints) { ep in Text(ep.title).tag(Optional(ep)) }
                }
                .pickerStyle(.inline).labelsHidden()
                Button("How this Mac resolves names…") { model.showMacResolvers = true }
            }
        }
        Section("Public resolvers") {
            ForEach(model.presetsNeedingSetup) { p in
                Button("\(p.name)… (needs your \(PresetFields.label(p.requires?.first ?? "").lowercased()))") { model.setupPreset = p.id }
            }
            ForEach(model.providers) { p in
                Menu {
                    Picker("", selection: $selection) {
                        ForEach(p.primary) { ep in Text(TransportName.display(ep.transport)).tag(Optional(ep)) }
                    }
                    .pickerStyle(.inline).labelsHidden()
                    Divider()
                    Menu("More addresses") {
                        Picker("", selection: $selection) {
                            ForEach(p.all) { ep in Text(ep.title).tag(Optional(ep)) }
                        }
                        .pickerStyle(.inline).labelsHidden()
                    }
                    if !p.requires.isEmpty {
                        Button("Change \(PresetFields.label(p.requires[0]).lowercased())…") { model.setupPreset = p.presetID }
                    }
                } label: {
                    if let s = selection, p.all.contains(s) {
                        Label(p.name, systemImage: "checkmark")
                    } else {
                        Text(p.name)
                    }
                }
            }
        }
        if !model.customEndpoints.isEmpty {
            Section("Custom") {
                Picker("", selection: $selection) {
                    ForEach(model.customEndpoints) { ep in Text(ep.title).tag(Optional(ep)) }
                }
                .pickerStyle(.inline).labelsHidden()
            }
        }
    }
}

/// The resolver token when Query asks several resolvers: a checklist, with a
/// way back to asking one.
struct CompareEndpointPicker: View {
    @EnvironmentObject var model: AppModel
    @Binding var open: Bool
    var addResolver: () -> Void

    var body: some View {
        Button {
            open.toggle()
        } label: {
            Label { Text(verbatim: "\(model.compareSelection.count) resolvers") } icon: { Image(systemName: "checklist") }.font(.callout)
        }
        .buttonStyle(.plain)
        .tokenChrome()
        .popover(isPresented: $open) {
            VStack(spacing: 0) {
                // The way back sits in a header that never scrolls away.
                HStack {
                    Text("Ask these resolvers").font(.headline)
                    Spacer()
                    Button("Ask one resolver") { open = false; model.severalResolvers = false }
                }
                .padding(12)
                Divider()
                ScrollView {
                    VStack(alignment: .leading, spacing: 6) {
                        if !model.systemEndpoints.isEmpty {
                            Text("This Mac").font(.caption).foregroundStyle(.secondary)
                            ForEach(model.systemEndpoints) { ep in EndpointCheckbox(endpoint: ep) }
                        }
                        Text("Public resolvers").font(.caption).foregroundStyle(.secondary).padding(.top, 6)
                        ForEach(model.providers) { p in ProviderChecklistRow(provider: p) }
                        if !model.customEndpoints.isEmpty {
                            Text("Custom").font(.caption).foregroundStyle(.secondary).padding(.top, 6)
                            ForEach(model.customEndpoints) { ep in EndpointCheckbox(endpoint: ep) }
                        }
                    }
                    .padding(12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                Divider()
                HStack {
                    Button("Add resolver…") { open = false; addResolver() }
                    Spacer()
                }
                .padding(12)
            }
            .frame(width: 340, height: 440)
        }
    }
}

/// The query options button. It stays quiet at the defaults and says how
/// many options are changed otherwise, so a forgotten RD=0 cannot silently
/// skew results.
struct OptionsButton: View {
    @Binding var options: Options
    @Binding var validate: Bool
    var showsValidate: Bool
    @State private var open = false

    var body: some View {
        let changed = (showsValidate && !validate ? ["validation off"] : []) + options.changed
        Button { open.toggle() } label: {
            if changed.isEmpty {
                Image(systemName: "slider.horizontal.3")
            } else {
                Label(changed.count == 1 ? changed[0] : "\(changed.count) options changed", systemImage: "slider.horizontal.3")
                    .foregroundStyle(Color.accentColor)
            }
        }
        .help(changed.isEmpty ? "Query options (all at their defaults)" : "Changed from the defaults: " + changed.joined(separator: ", "))
        .controlSize(.extraLarge)
        .popover(isPresented: $open) { OptionsView(options: $options, validate: $validate, showsValidate: showsValidate).padding() }
    }
}

struct OptionsView: View {
    @Binding var options: Options
    @Binding var validate: Bool
    var showsValidate: Bool

    var body: some View {
        Form {
            if showsValidate {
                Toggle("Validate DNSSEC", isOn: $validate)
                    .help("Nordyg checks the chain of trust from the root itself, instead of trusting the resolver's AD flag. Costs a few extra queries.")
                Divider()
            }
            Toggle("Recursion desired (RD)", isOn: bind(\.recursionDesired, true))
            Toggle("DNSSEC OK (DO)", isOn: bind(\.dnssecOk, true))
            Toggle("Checking disabled (CD)", isOn: bind(\.checkingDisabled, false))
            Toggle("EDNS", isOn: bind(\.edns, true))
            Toggle("TCP fallback on truncation", isOn: bind(\.tcpFallback, true))
            Toggle("Request NSID", isOn: bind(\.nsid, false))
            Toggle("Send cookie", isOn: bind(\.cookie, false))
            Stepper(value: Binding(get: { options.udpSize ?? 1232 }, set: { options.udpSize = $0 }), in: 512...4096, step: 256) {
                Text(verbatim: "UDP size: \(options.udpSize ?? 1232)")
            }
            Stepper(value: Binding(get: { options.timeoutMs ?? 5000 }, set: { options.timeoutMs = $0 }), in: 500...30000, step: 500) {
                Text(verbatim: "Timeout: \(options.timeoutMs ?? 5000) ms")
            }
            if !options.changed.isEmpty || (showsValidate && !validate) {
                Button("Reset to defaults") { options = Options(); validate = true }
            }
        }
        .frame(width: 300)
    }

    private func bind(_ key: WritableKeyPath<Options, Bool?>, _ def: Bool) -> Binding<Bool> {
        Binding(get: { options[keyPath: key] ?? def }, set: { options[keyPath: key] = $0 })
    }
}

struct CustomEndpointSheet: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var transport = "udp"
    @State private var address = ""
    @State private var tlsName = ""
    @State private var url = ""
    @State private var label = ""
    @State private var problem: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Custom resolver").font(.headline)
            Picker("Transport", selection: $transport) {
                Text("UDP").tag("udp"); Text("TCP").tag("tcp"); Text("DoT").tag("dot"); Text("DoH").tag("doh"); Text("DoQ").tag("doq")
            }
            .pickerStyle(.segmented)
            if transport == "doh" {
                TextField("URL (https://…/dns-query)", text: $url)
                TextField("IP address to pin (optional, ip:443)", text: $address)
            } else {
                TextField("IP address (ip or ip:port)", text: $address)
            }
            if transport == "dot" || transport == "doq" {
                TextField("TLS name (e.g. dns.quad9.net)", text: $tlsName)
            }
            TextField("Label (optional)", text: $label)
            if let problem { Text(problem).foregroundStyle(.red).font(.callout) }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Add") { add() }.keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent)
            }
        }
        .textFieldStyle(.roundedBorder)
        .padding(20)
        .frame(width: 420)
    }

    private func add() {
        var addr = address.trimmingCharacters(in: .whitespaces)
        let defaultPort = (transport == "dot" || transport == "doq") ? 853 : (transport == "doh" ? 443 : 53)
        if !addr.isEmpty, isIPAddress(addr) { addr = SystemResolvers.hostPort(addr, defaultPort) }
        if transport != "doh", addr.isEmpty { problem = "An IP address is required."; return }
        if transport == "doh", !url.hasPrefix("https://") { problem = "The URL must start with https://"; return }
        if (transport == "dot" || transport == "doq"), tlsName.isEmpty { problem = "A TLS name is required."; return }
        let ep = Endpoint(transport: transport,
                          address: addr.isEmpty ? nil : addr,
                          tlsName: tlsName.isEmpty ? nil : tlsName,
                          url: transport == "doh" ? url : nil,
                          method: nil,
                          label: label.isEmpty ? nil : label)
        model.addCustom(ep)
        dismiss()
    }
}

struct EndpointCheckbox: View {
    @EnvironmentObject var model: AppModel
    var endpoint: Endpoint
    var title: String?
    var body: some View {
        Toggle(title ?? endpoint.title, isOn: Binding(
            get: { model.compareSelection.contains(endpoint) },
            set: { on in if on { model.compareSelection.insert(endpoint) } else { model.compareSelection.remove(endpoint) } }
        ))
        .toggleStyle(.checkbox)
    }
}

/// One provider in the several-resolvers checklist: a checkbox, the transport
/// to ask it over, and its other addresses on demand.
struct ProviderChecklistRow: View {
    @EnvironmentObject var model: AppModel
    var provider: Provider
    @State private var expanded = false
    @State private var picked: String?

    private var selectedPrimary: Endpoint? { provider.primary.first { model.compareSelection.contains($0) } }
    private var transport: String { picked ?? selectedPrimary?.transport ?? provider.primary.first?.transport ?? "udp" }
    private var isOn: Bool { provider.all.contains { model.compareSelection.contains($0) } }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Toggle(provider.name, isOn: Binding(
                    get: { isOn },
                    set: { on in
                        if on, let ep = provider.primary.first(where: { $0.transport == transport }) {
                            model.compareSelection.insert(ep)
                        } else if !on {
                            provider.all.forEach { model.compareSelection.remove($0) }
                        }
                    }
                ))
                .toggleStyle(.checkbox)
                Spacer()
                Picker("", selection: Binding(
                    get: { transport },
                    set: { t in
                        // Swap the asked address to the new transport.
                        if let old = selectedPrimary, let new = provider.primary.first(where: { $0.transport == t }) {
                            model.compareSelection.remove(old)
                            model.compareSelection.insert(new)
                        }
                        picked = t
                    }
                )) {
                    ForEach(provider.primary) { ep in Text(TransportName.display(ep.transport)).tag(ep.transport) }
                }
                .pickerStyle(.menu).labelsHidden()
                .frame(width: 84)
                .help("Transport to ask \(provider.name) over")
                Button { expanded.toggle() } label: { Image(systemName: expanded ? "chevron.up" : "ellipsis") }
                    .buttonStyle(.borderless)
                    .help(expanded ? "Fewer addresses" : "More addresses: IPv6, secondary, every transport")
            }
            if expanded {
                ForEach(provider.all) { ep in EndpointCheckbox(endpoint: ep).padding(.leading, 22).font(.callout) }
            }
        }
    }
}

/// Labels and checks for the values presets ask for.
enum PresetFields {
    static func label(_ key: String) -> String {
        switch key {
        case "profile_id": return "Profile ID"
        default: return key.replacingOccurrences(of: "_", with: " ").capitalizedFirst
        }
    }

    static func help(_ presetID: String, _ key: String) -> String {
        switch (presetID, key) {
        case ("nextdns", "profile_id"):
            return "Find it on my.nextdns.io under Setup: the 6 characters in abc123.dns.nextdns.io. Queries then use your NextDNS configuration, its blocklists and its logs."
        default:
            return "The value your provider gave you."
        }
    }

    /// Nil when fine, otherwise what is wrong.
    static func problem(_ key: String, _ value: String) -> String? {
        let v = value.trimmingCharacters(in: .whitespaces).lowercased()
        if v.isEmpty { return "Enter a value." }
        if key == "profile_id", v.range(of: "^[0-9a-f]{6}$", options: .regularExpression) == nil {
            return "A NextDNS profile ID is 6 characters, digits and a to f, like abc123."
        }
        if v.range(of: "^[a-z0-9-]+$", options: .regularExpression) == nil {
            return "Only letters, digits and dashes."
        }
        return nil
    }
}

/// Asks for the values a preset needs (NextDNS's profile ID).
struct PresetSetupSheet: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) private var dismiss
    var preset: Preset
    @State private var values: [String: String] = [:]
    @State private var problem: String?

    var body: some View {
        let keys = preset.requires ?? []
        VStack(alignment: .leading, spacing: 12) {
            Text(preset.name).font(.headline)
            ForEach(keys, id: \.self) { k in
                VStack(alignment: .leading, spacing: 4) {
                    TextField(PresetFields.label(k), text: Binding(get: { values[k] ?? "" }, set: { values[k] = $0 }))
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.body, design: .monospaced))
                        .onSubmit(save)
                    Text(PresetFields.help(preset.id, k)).font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            if let problem { Text(problem).foregroundStyle(.red).font(.callout) }
            HStack {
                if keys.contains(where: { model.presetValues[$0] != nil }) {
                    Button("Remove", role: .destructive) { model.clearPreset(preset.id); dismiss() }
                }
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Save") { save() }.keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent)
            }
        }
        .padding(20)
        .frame(width: 440)
        .onAppear { for k in keys { values[k] = model.presetValues[k] ?? "" } }
    }

    private func save() {
        var clean: [String: String] = [:]
        for k in preset.requires ?? [] {
            let v = (values[k] ?? "").trimmingCharacters(in: .whitespaces).lowercased()
            if let p = PresetFields.problem(k, v) { problem = p; return }
            clean[k] = v
        }
        model.configurePreset(preset.id, values: clean)
        dismiss()
    }
}
