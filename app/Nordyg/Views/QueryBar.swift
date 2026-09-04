import SwiftUI

struct QueryBar: View {
    @EnvironmentObject var model: AppModel
    @State private var showCustom = false
    @State private var showOptions = false
    @FocusState private var nameFocused: Bool

    var body: some View {
        VStack(spacing: 8) {
            HStack(spacing: 8) {
                TextField("Name or IP address", text: $model.name)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))
                    .focused($nameFocused)
                    .onSubmit { model.run() }
                    .frame(minWidth: 240)

                Picker("Type", selection: $model.type) {
                    ForEach(RecordTypes.all, id: \.self) { Text($0).tag($0) }
                }
                .labelsHidden()
                .frame(width: 96)

                Picker("Mode", selection: $model.mode) {
                    ForEach(Mode.allCases) { Text($0.title).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .frame(width: 220)

                if model.isRunning {
                    Button("Cancel") { model.cancel() }
                    ProgressView().controlSize(.small)
                } else {
                    Button("Run") { model.run() }
                        .keyboardShortcut(.defaultAction)
                        .disabled(!model.canRun)
                        .buttonStyle(.borderedProminent)
                }
            }

            HStack(spacing: 8) {
                switch model.mode {
                case .query:
                    EndpointPicker(selection: $model.selected)
                    Button { showCustom = true } label: { Image(systemName: "plus") }
                        .help("Add a custom resolver")
                case .compare:
                    CompareEndpointPicker()
                    Button { showCustom = true } label: { Image(systemName: "plus") }
                        .help("Add a custom resolver")
                case .trace:
                    Text("Iterative from the root servers").foregroundStyle(.secondary)
                }
                Spacer()
                if model.mode != .compare {
                    Toggle("Validate DNSSEC", isOn: $model.validate).toggleStyle(.checkbox)
                }
                Button { showOptions.toggle() } label: { Image(systemName: "slider.horizontal.3") }
                    .help("Query options")
                    .popover(isPresented: $showOptions) { OptionsView(options: $model.options).padding() }
            }
            .font(.callout)
        }
        .padding(12)
        .sheet(isPresented: $showCustom) { CustomEndpointSheet() }
        .onAppear { nameFocused = true }
    }
}

struct EndpointPicker: View {
    @EnvironmentObject var model: AppModel
    @Binding var selection: Endpoint?

    var body: some View {
        Picker("Resolver", selection: $selection) {
            if !model.systemEndpoints.isEmpty {
                Section("System") {
                    ForEach(model.systemEndpoints) { ep in Text(ep.title).tag(Optional(ep)) }
                }
            }
            ForEach(model.presets) { p in
                let usable = p.endpoints.filter { !$0.needsPlaceholder }
                if !usable.isEmpty {
                    Section(p.name) {
                        ForEach(usable) { ep in Text(ep.title).tag(Optional(ep)) }
                    }
                }
            }
            if !model.customEndpoints.isEmpty {
                Section("Custom") {
                    ForEach(model.customEndpoints) { ep in Text(ep.title).tag(Optional(ep)) }
                }
            }
        }
        .frame(maxWidth: 360)
    }
}

struct CompareEndpointPicker: View {
    @EnvironmentObject var model: AppModel
    @State private var open = false

    var body: some View {
        Button {
            open.toggle()
        } label: {
            Label("\(model.compareSelection.count) resolvers", systemImage: "checklist")
        }
        .popover(isPresented: $open) {
            ScrollView {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(groups, id: \.0) { title, eps in
                        Text(title).font(.caption).foregroundStyle(.secondary).padding(.top, 6)
                        ForEach(eps) { ep in
                            Toggle(ep.title, isOn: Binding(
                                get: { model.compareSelection.contains(ep) },
                                set: { on in if on { model.compareSelection.insert(ep) } else { model.compareSelection.remove(ep) } }
                            )).toggleStyle(.checkbox)
                        }
                    }
                }
                .padding(12)
            }
            .frame(width: 320, height: 400)
        }
    }

    private var groups: [(String, [Endpoint])] {
        var out: [(String, [Endpoint])] = []
        if !model.systemEndpoints.isEmpty { out.append(("System", model.systemEndpoints)) }
        for p in model.presets {
            let usable = p.endpoints.filter { !$0.needsPlaceholder }
            if !usable.isEmpty { out.append((p.name, usable)) }
        }
        if !model.customEndpoints.isEmpty { out.append(("Custom", model.customEndpoints)) }
        return out
    }
}

struct OptionsView: View {
    @Binding var options: Options

    var body: some View {
        Form {
            Toggle("Recursion desired (RD)", isOn: bind(\.recursionDesired, true))
            Toggle("DNSSEC OK (DO)", isOn: bind(\.dnssecOk, true))
            Toggle("Checking disabled (CD)", isOn: bind(\.checkingDisabled, false))
            Toggle("EDNS", isOn: bind(\.edns, true))
            Toggle("TCP fallback on truncation", isOn: bind(\.tcpFallback, true))
            Toggle("Request NSID", isOn: bind(\.nsid, false))
            Toggle("Send cookie", isOn: bind(\.cookie, false))
            Stepper("UDP size: \(options.udpSize ?? 1232)", value: Binding(get: { options.udpSize ?? 1232 }, set: { options.udpSize = $0 }), in: 512...4096, step: 256)
            Stepper("Timeout: \(options.timeoutMs ?? 5000) ms", value: Binding(get: { options.timeoutMs ?? 5000 }, set: { options.timeoutMs = $0 }), in: 500...30000, step: 500)
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
