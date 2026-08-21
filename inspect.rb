#!/usr/bin/env ruby
# frozen_string_literal: true
#
# --inspect's rendering half. unwind-check (C++) does the actual CFI
# checking and hands us, on stdin, a JSON array of address-keyed
# annotations (declared CFI rows, converged abstract state, findings).
# We run objdump --visualize-jumps over the same address range -- it
# already draws jump-arrow gutters and colorizes disassembly better than
# we'd bother to reimplement -- and splice our annotations into its
# output by address, printing the merged, still-colored listing straight
# to our own stdout.
#
# Deliberately strict: an objdump output line that isn't one we
# recognize, or an annotation address objdump's listing never printed,
# is a hard failure rather than a silently incomplete listing. Same rule
# the rest of unwind-check follows -- say why, don't guess.

require 'json'
require 'open3'

def die(msg)
  warn "inspect.rb: #{msg}"
  exit 1
end

binary_path, start_hex, stop_hex, color_flag = ARGV
if binary_path.nil? || start_hex.nil? || stop_hex.nil? || color_flag.nil?
  die 'usage: inspect.rb <binary> <start-hex> <stop-hex> <color:0|1>'
end
color = color_flag == '1'

annotations =
  begin
    JSON.parse($stdin.read)
  rescue JSON::ParserError => e
    die "malformed annotations JSON on stdin: #{e.message}"
  end

# Within one address, a fixed render order regardless of the order
# unwind-check emitted them in.
KIND_ORDER = { 'cfi_row' => 0, 'state' => 1, 'guessed' => 2, 'finding' => 3 }.freeze

by_pc = Hash.new { |h, k| h[k] = [] }
annotations.each do |a|
  by_pc[Integer(a.fetch('pc'))] << a
end
by_pc.each_value { |list| list.sort_by! { |a| KIND_ORDER.fetch(a.fetch('kind')) } }

RESET = "\e[0m"
DIM = "\e[2m"
RED = "\e[31m"
YELLOW = "\e[33m"

def colorize(text, code)
  "#{code}#{text}#{RESET}"
end

def render_annotation(a, color)
  case a.fetch('kind')
  when 'cfi_row'
    text = a.fetch('text')
    '    ' + (color ? colorize(text, DIM) : text)
  when 'state'
    text = "state: #{a.fetch('text')}"
    '    ' + (color ? colorize(text, DIM) : text)
  when 'guessed'
    text = "guessed: #{a.fetch('text')}"
    '    ' + (color ? colorize(text, YELLOW) : text)
  when 'finding'
    severity = a.fetch('severity')
    label = severity == 'mismatch' ? 'MISMATCH' : 'REVIEW'
    repeats = a['repeats'] ? " [and at #{a['repeats']} more addresses]" : ''
    text = "#{label}: #{a.fetch('text')}#{repeats}"
    '    ' + (color ? colorize(text, severity == 'mismatch' ? RED : YELLOW) : text)
  else
    die "annotation with unknown kind: #{a.inspect}"
  end
end

objdump_argv = ['objdump', '-d', "--start-address=#{start_hex}", "--stop-address=#{stop_hex}"]
objdump_argv += color ? ['--visualize-jumps=extended-color', '--disassembler-color=extended'] : ['--visualize-jumps']
objdump_argv << binary_path

# Lines objdump legitimately prints with no leading address: the
# file-format banner, blank separators, the section header, and the
# "<addr> <symbol>:" line that starts each contiguous disassembled run.
PASSTHROUGH_LINE = [
  /\A\s*\z/,
  /\bfile format \S+\s*\z/,
  /\ADisassembly of section /,
  /\A[0-9a-fA-F]+ <.*>:\s*\z/,
].freeze

# The address column: "    <hex>:\t...". Plain text, never colored, so
# this doesn't need to know anything about --disassembler-color.
ADDRESS_LINE = /\A\s*([0-9a-fA-F]+):\t/.freeze

seen_pcs = {}

begin
  puts "objdump_argv: #{objdump_argv.inspect}"
  Open3.popen2(*objdump_argv) do |stdin, stdout, wait_thr|
    stdin.close
    stdout.each_line do |line|
      m = ADDRESS_LINE.match(line)
      if m
        pc = Integer(m[1], 16)
        seen_pcs[pc] = true
        by_pc[pc].each { |a| puts render_annotation(a, color) }
        print line
      elsif PASSTHROUGH_LINE.any? { |re| re.match?(line) }
        print line
      else
        die "unrecognized objdump output line: #{line.inspect}"
      end
    end
    status = wait_thr.value
    die "objdump exited with status #{status.exitstatus}" unless status.success?
  end
rescue Errno::ENOENT => e
  die "exec-ing objdump failed: #{e.message}"
end

missing = by_pc.keys.reject { |pc| seen_pcs[pc] }
unless missing.empty?
  die "objdump's listing never printed address(es) we had annotations for: " \
      "#{missing.sort.map { |pc| format('0x%x', pc) }.join(', ')}"
end
