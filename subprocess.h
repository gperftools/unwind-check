/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#ifndef SUBPROCESS_H_
#define SUBPROCESS_H_

#include <sys/types.h>

#include <string>
#include <vector>

#include "absl/status/statusor.h"

namespace unwind_analysis {

// A child process spawned with posix_spawn -- argv goes straight to
// exec, never through a shell, so nothing (a path with spaces, a symbol
// name with a shell metacharacter) needs escaping and nothing can be
// smuggled into a command line.
struct Subprocess {
  pid_t pid = -1;
  // -1 unless the matching SpawnOptions field asked for a pipe.
  int stdin_fd = -1;   // parent writes here; close when done writing
  int stdout_fd = -1;  // parent reads here
};

struct SpawnOptions {
  bool pipe_stdin = false;      // false: child inherits this process's stdin
  bool pipe_stdout = false;     // false: child inherits this process's stdout
  bool discard_stderr = false;  // redirect the child's stderr to /dev/null
};

// Spawns argv[0] (resolved via $PATH unless it contains a '/', same as
// execvp) with the given argv. Fails only when posix_spawn itself
// fails -- returns absl::InternalError with strerror() text, verbatim
// and with no editorializing: the caller knows its own context (a
// missing addr2line is a quiet degrade, a missing ruby for --inspect is
// a hard failure) far better than a canned message here would.
absl::StatusOr<Subprocess> SpawnProcess(const std::vector<std::string>& argv, const SpawnOptions& options);

// Waits for `pid`, returning its exit status via WEXITSTATUS, or -1 if
// it did not exit normally (killed by a signal, etc).
int WaitForProcess(pid_t pid);

}  // namespace unwind_analysis

#endif  // SUBPROCESS_H_
