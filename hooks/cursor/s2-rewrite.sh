#!/bin/sh
# s2 Cursor IDE hook — wraps commands with s2 exec for secret injection.
# Install: add to ~/.cursor/hooks.json as a PreToolUse hook.
exec s2 hook --format cursor
