# Nordyg build. Targets:
#   make test     run Go tests
#   make archive  build the universal static library core/build/libnordyg.a + header
#   make smoke    build and run the Swift bridge harness against the archive
#   make lint     golangci-lint on the core
#   make app      build the SwiftUI app (Debug, ad-hoc signed)
#   make run      build and open the app
#   make xcodeproj regenerate app/Nordyg.xcodeproj from app/project.yml
#   make clean
#
# Go is pinned via GOTOOLCHAIN so the version on PATH does not matter.

GO_VERSION      := 1.27.0
export GOTOOLCHAIN := go$(GO_VERSION)
export CGO_ENABLED := 1

# App Store minimum. Keep in sync with the Xcode deployment target.
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

.PHONY: all test archive smoke lint clean

all: archive

test:
	cd $(CORE) && go test ./...

lint:
	cd $(CORE) && golangci-lint run ./...

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
             app/Nordyg/Core/JSONValue.swift app/Nordyg/Core/SystemResolvers.swift app/Nordyg/Core/SystemLookup.swift

$(SMOKE): archive $(SMOKE_SRC)
	@mkdir -p app/build
	swiftc -parse-as-library -I app/NordygCore $(SMOKE_SRC) -L$(BUILD) -lnordyg -lresolv \
	  -framework CoreFoundation -framework Security -framework SystemConfiguration -o $@
	codesign --force --sign - --options runtime $@

smoke: $(SMOKE)
	$(SMOKE)

# --- SwiftUI app ---------------------------------------------------------------

XCODEPROJ := app/Nordyg.xcodeproj
DERIVED   := app/build/DerivedData
APP       := $(DERIVED)/Build/Products/Debug/Nordyg.app

.PHONY: xcodeproj app run

# Regenerate the Xcode project from app/project.yml (needs xcodegen).
xcodeproj:
	cd app && xcodegen generate

# Debug build of the app, ad-hoc signed (no team needed).
app: archive
	xcodebuild -project $(XCODEPROJ) -scheme Nordyg -configuration Debug \
	  -derivedDataPath $(DERIVED) CODE_SIGN_IDENTITY=- CODE_SIGNING_REQUIRED=NO build \
	  | grep -E 'error:|warning: .*\.swift|BUILD' || true
	@test -d $(APP)

run: app
	open $(APP)

clean:
	rm -rf $(BUILD) app/build $(APP_HDR)
