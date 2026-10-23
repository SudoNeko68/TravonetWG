export GO111MODULE := on
MAKEFLAGS += --no-print-directory

ANDROID_NDK_HOME ?=
GO_BIN ?= go

.PHONY: all android test vet clean

all: android

android:
	GO_BIN="$(GO_BIN)" ANDROID_NDK_HOME="$(ANDROID_NDK_HOME)" ./build-android.sh

test:
	$(GO_BIN) test ./conf ./conn ./proxy

vet:
	$(GO_BIN) vet ./...

clean:
	rm -rf build/android

