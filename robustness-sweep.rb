#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Runs unwind-check over a sample of system binaries and reports anything
# that crashed, hung, or came out slow. This is the non-hermetic
# counterpart to `bazel test :all`: the fixtures prove the analysis is
# right, this proves the parser survives real-world input.
#
#   ./robustness-sweep.rb [count] [-jN] [-v]     # default count 400, -j1
#
# -v prints one line per binary as its result comes in (path, time,
# verdict counts), so you can find the ones worth digging into --
# sort by mismatch/review count or by time -- without a separate run.
#
# Anything printed as ABNORMAL is a bug in this tool: the only exit codes
# it may produce are 0 (all blessed), 1 (a mismatch), 2 (review) and
# 3 (the run failed cleanly).

require 'open3'

BIN = ENV['BIN'] || './bazel-bin/unwind-check'
TIMEOUT_SECS = 120
SLOW_MS = 5000
SEED = Integer(ENV['SWEEP_SEED'] || 0)

SUMMARY_RE = /^(\d+) FDEs: (\d+) blessed, (\d+) review-light, (\d+) review, (\d+) mismatch$/

def die(msg)
  warn msg
  exit 1
end

def parse_args(argv)
  count = 400
  jobs = 1
  verbose = false
  argv.each do |arg|
    case arg
    when /\A-j(\d+)\z/ then jobs = $1.to_i
    when '-v' then verbose = true
    when /\A\d+\z/ then count = arg.to_i
    else die "unrecognized argument: #{arg}"
    end
  end
  die '-jN needs N >= 1' if jobs < 1
  [count, jobs, verbose]
end

# Candidate binaries, deduped by realpath so the many .so.N -> .so.N.N.N
# symlinks in /usr/lib don't make us check the same file repeatedly.
def candidate_binaries
  paths = Dir.glob('/usr/lib/x86_64-linux-gnu/*.so.*') + Dir.glob('/usr/bin/*')
  paths.filter_map { |p| File.realpath(p) rescue nil }
       .uniq
       .select { |p| File.file?(p) && elf?(p) }
end

def elf?(path)
  File.binread(path, 4) == "\x7fELF"
rescue SystemCallError
  false
end

# One FDE-summary line, e.g. "42 FDEs: 40 blessed, 0 review-light, 1 review, 1 mismatch".
Totals = Struct.new(:fdes, :blessed, :review_light, :review, :mismatch) do
  def +(other)
    Totals.new(*members.map { |m| self[m] + other[m] })
  end
end
ZERO_TOTALS = Totals.new(0, 0, 0, 0, 0)

Result = Struct.new(:path, :rc, :elapsed_ms, :totals, :abnormal)

def check_binary(path)
  start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  out, _err, status = Open3.capture3('timeout', TIMEOUT_SECS.to_s, BIN, '--summary_only', '--addr2line=off', path)
  elapsed_ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - start) * 1000).round
  rc = status.exitstatus || -1

  if rc > 3
    return Result.new(path, rc, elapsed_ms, ZERO_TOTALS, true)
  end

  m = SUMMARY_RE.match(out)
  totals = m ? Totals.new(*m.captures.map(&:to_i)) : ZERO_TOTALS
  Result.new(path, rc, elapsed_ms, totals, false)
end

# Runs `jobs` concurrent checks, driven by a pipe-of-tokens: `jobs` bytes
# are written to a pipe up front (assumed to fit in one write -- true for
# any sane N against the kernel's default 64KiB pipe capacity). The main
# thread reads one token per binary before spawning that binary's worker
# thread, so it blocks (spawning no new thread) once all tokens are
# checked out, and the worker writes its token back when done. Same
# trick make's jobserver uses to bound concurrency across independent
# workers without a shared counter -- and it keeps the thread count itself
# down to `jobs` instead of one per binary.
def run_sweep(binaries, jobs, verbose: false)
  token_read, token_write = IO.pipe
  token_write.write("\0" * jobs)

  print_mutex = Mutex.new
  results = Array.new(binaries.size)
  threads = binaries.each_with_index.map do |path, i|
    token = token_read.read(1)  # blocks here, in the main thread, until a slot frees up
    Thread.new do
      begin
        r = check_binary(path)
        results[i] = r
        if r.abnormal
          print_mutex.synchronize { puts "ABNORMAL rc=#{r.rc} #{r.elapsed_ms}ms #{path}" }
        elsif verbose
          t = r.totals
          print_mutex.synchronize do
            puts "#{r.elapsed_ms}ms fdes=#{t.fdes} blessed=#{t.blessed} " \
                 "review_light=#{t.review_light} review=#{t.review} mismatch=#{t.mismatch}  #{path}"
          end
        end
      ensure
        token_write.write(token)
      end
    end
  end
  threads.each(&:join)
  token_read.close
  token_write.close
  results
end

def main
  die "no #{BIN}; run: bazel build -c opt :unwind-check" unless File.executable?(BIN)

  count, jobs, verbose = parse_args(ARGV)
  binaries = candidate_binaries.shuffle(random: Random.new(SEED)).first(count)

  results = run_sweep(binaries, jobs, verbose: verbose)

  abnormal = results.count(&:abnormal)
  totals = results.reject(&:abnormal).reduce(ZERO_TOTALS) { |acc, r| acc + r.totals }
  slow = results.reject(&:abnormal)
                .select { |r| r.elapsed_ms > SLOW_MS }
                .map { |r| "#{r.elapsed_ms}ms:#{File.basename(r.path)}" }

  puts "binaries=#{results.size} abnormal_exits=#{abnormal}"
  puts "totals: fdes=#{totals.fdes} blessed=#{totals.blessed} " \
       "review_light=#{totals.review_light} review=#{totals.review} mismatch=#{totals.mismatch}"
  puts "slow_over_5s:#{slow.map { |s| " #{s}" }.join}"

  exit(abnormal.zero? ? 0 : 1)
end

main
