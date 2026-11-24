# Nordyg build. Targets:
#   make test     run Go tests (uncached, since they also write the samples make smoke decodes)
#   make archive  build the universal static library core/build/libnordyg.a + header
#   make smoke    build and run the Swift bridge harness against the archive
#   make lint     golangci-lint on the core, swift format lint on the app
#   make format   rewrite the app's Swift in the house format (app/.swift-format)
#   make app      build the SwiftUI app (Debug, ad-hoc signed)
#   make run      build and open the app
#   make debug-tool  build app/build/nordyg-debug, which drives a running Debug build
#   make xcodeproj regenerate app/Nordyg.xcodeproj from app/project.yml
#   make icon     put app/design/logo.svg into AppIcon.icon and render the site PNGs
#   make landing  build the website (landing/dist); make landing-dev runs the dev server
#   make clean
#
# Go is pinned via GOTOOLCHAIN so the version on PATH does not matter.

GO_VERSION      := 1.27.4
export GOTOOLCHAIN := go$(GO_VERSION)
export CGO_ENABLED := 1

# Oldest macOS the app runs on. Keep in sync with the Xcode deployment target.
MACOSX_MIN      := 14.0
export CGO_CFLAGS  := -mmacosx-version-min=$(MACOSX_MIN)
export CGO_LDFLAGS := -mmacosx-version-min=$(MACOSX_MIN)

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -X github.com/n0rdy/nordyg/core/internal/ops.Version=$(VERSION)

CORE     := core
BUILD    := $(CORE)/build
PKG      := ./cmd/libnordyg
GO_SRC   := $(shell find $(CORE) -name '*.go' -not -path '$(BUILD)/*') $(CORE)/go.mod $(CORE)/go.sum

APP_HDR  := app/NordygCore/libnordyg.h
SMOKE    := app/build/nordyg-smoke
# One result of every op, written by the Go tests from their fixtures, for the
# smoke harness to decode with the app's own types.
SAMPLES  := app/build/samples

.PHONY: all test archive smoke lint format clean

all: archive

test:
	@rm -rf $(SAMPLES) && mkdir -p $(SAMPLES)
	cd $(CORE) && NORDYG_SAMPLES=$(abspath $(SAMPLES)) go test -count=1 ./...
	@touch $(SAMPLES)/.stamp

SWIFT_SRC := app/Nordyg app/smoke app/tools

lint:
	cd $(CORE) && golangci-lint run ./...
	swift format lint --strict -r $(SWIFT_SRC)

format:
	swift format format -i -r $(SWIFT_SRC)

$(BUILD)/libnordyg_amd64.a: $(GO_SRC)
	@mkdir -p $(BUILD)
	cd $(CORE) && GOOS=darwin GOARCH=amd64 go build -buildmode=c-archive -ldflags '$(LDFLAGS)' -o build/libnordyg_amd64.a $(PKG)

$(BUILD)/libnordyg_arm64.a: $(GO_SRC)
	@mkdir -p $(BUILD)
	cd $(CORE) && GOOS=darwin GOARCH=arm64 go build -buildmode=c-archive -ldflags '$(LDFLAGS)' -o build/libnordyg_arm64.a $(PKG)

$(BUILD)/libnordyg.a: $(BUILD)/libnordyg_amd64.a $(BUILD)/libnordyg_arm64.a
	lipo -create $^ -output $@
	lipo -info $@

# The header is architecture independent; take the amd64 one.
$(BUILD)/libnordyg.h: $(BUILD)/libnordyg_amd64.a
	cp $(BUILD)/libnordyg_amd64.h $@

$(APP_HDR): $(BUILD)/libnordyg.h
	cp $< $@

archive: $(BUILD)/libnordyg.a $(APP_HDR)

SMOKE_SRC := app/smoke/main.swift app/Nordyg/Core/CoreBridge.swift app/Nordyg/Core/Contract.swift \
             app/Nordyg/Core/JSONValue.swift app/Nordyg/Core/SystemResolvers.swift app/Nordyg/Core/SystemLookup.swift app/Nordyg/Core/DNSConfiguration.swift

$(SMOKE): archive $(SMOKE_SRC)
	@mkdir -p app/build
	swiftc -parse-as-library -I app/NordygCore $(SMOKE_SRC) -L$(BUILD) -lnordyg -lresolv \
	  -framework CoreFoundation -framework Security -framework SystemConfiguration -o $@
	codesign --force --sign - --options runtime $@

# make test leaves the samples behind. They are rebuilt here only when the Go
# sources are newer, so CI's test step is the one run of the suite.
$(SAMPLES)/.stamp: $(GO_SRC)
	$(MAKE) test

smoke: $(SMOKE) $(SAMPLES)/.stamp
	NORDYG_SAMPLES=$(SAMPLES) $(SMOKE)

# --- SwiftUI app ---------------------------------------------------------------

XCODEPROJ := app/Nordyg.xcodeproj
DERIVED   := app/build/DerivedData
APP       := $(DERIVED)/Build/Products/Debug/Nordyg.app

.PHONY: xcodeproj app run icon debug-tool

# Regenerate the Xcode project from app/project.yml (needs xcodegen).
xcodeproj:
	cd app && xcodegen generate

# Put the logo (app/design/logo.svg) into the Icon Composer package and
# render the site's PNGs from it. Regenerate the SVG first with
# app/design/logo.py when its geometry changes.
icon:
	swift app/tools/make-icon.swift app/design/logo.svg app/Nordyg/AppIcon.icon landing/public

# Debug build of the app, ad-hoc signed (no team needed).
app: archive
	xcodebuild -project $(XCODEPROJ) -scheme Nordyg -configuration Debug \
	  -derivedDataPath $(DERIVED) CODE_SIGN_IDENTITY=- CODE_SIGNING_REQUIRED=NO build \
	  | grep -E 'error:|warning: .*\.swift|BUILD' || true
	@test -d $(APP)

run: app
	open $(APP)

# Sends commands to a running Debug build (see app/Nordyg/DebugHooks.swift).
debug-tool: app/build/nordyg-debug

app/build/nordyg-debug: app/tools/nordyg-debug.swift
	@mkdir -p app/build
	swiftc -O -o $@ $<

# --- Website (plain Astro in landing/) -------------------------------------------

.PHONY: landing landing-dev

landing:
	cd landing && npm ci && npm run build

landing-dev:
	cd landing && npm install && npm run dev

clean:
	rm -rf $(BUILD) app/build $(APP_HDR) landing/dist
