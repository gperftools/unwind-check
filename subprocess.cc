/* -*- Mode: C++; c-basic-offset: 2; indent-tabs-mode: nil -*- */
#include "subprocess.h"

#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "absl/cleanup/cleanup.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"

extern char** environ;

namespace unwind_analysis {

namespace {

// Closes whichever of the two ends of a pipe pair are still valid (>= 0).
void ClosePipe(int fds[2]) {
  if (fds[0] >= 0) {
    close(fds[0]);
  }
  if (fds[1] >= 0) {
    close(fds[1]);
  }
}

}  // namespace

absl::StatusOr<Subprocess> SpawnProcess(const std::vector<std::string>& argv, const SpawnOptions& options) {
  if (argv.empty()) {
    return absl::InvalidArgumentError("SpawnProcess: empty argv");
  }

  // O_CLOEXEC on both ends of each pipe means we don't have to hand-close
  // the parent-only fd in the child: anything not explicitly kept open by
  // a file action below closes itself at the exec() inside posix_spawn.
  // posix_spawn_file_actions_adddup2's target fd comes back without
  // FD_CLOEXEC (same rule as real dup2), which is exactly the one fd each
  // side of the pipe needs to survive into the child.
  int stdin_pipe[2] = {-1, -1};
  int stdout_pipe[2] = {-1, -1};
  // Cancelled once each end has found its final owner (the child, via
  // exec, or the returned Subprocess); until then it closes whatever is
  // still open on every return path, success or not.
  absl::Cleanup pipe_closer = [&] {
    ClosePipe(stdin_pipe);
    ClosePipe(stdout_pipe);
  };
  if (options.pipe_stdin && pipe2(stdin_pipe, O_CLOEXEC) != 0) {
    return absl::InternalError(absl::StrCat("pipe(): ", strerror(errno)));
  }
  if (options.pipe_stdout && pipe2(stdout_pipe, O_CLOEXEC) != 0) {
    return absl::InternalError(absl::StrCat("pipe(): ", strerror(errno)));
  }

  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  if (options.pipe_stdin) {
    posix_spawn_file_actions_adddup2(&actions, stdin_pipe[0], STDIN_FILENO);
  }
  if (options.pipe_stdout) {
    posix_spawn_file_actions_adddup2(&actions, stdout_pipe[1], STDOUT_FILENO);
  }
  if (options.discard_stderr) {
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
  }

  std::vector<char*> cargv;
  cargv.reserve(argv.size() + 1);
  for (const std::string& a : argv) {
    cargv.push_back(const_cast<char*>(a.c_str()));
  }
  cargv.push_back(nullptr);

  pid_t pid = -1;
  int rc = posix_spawnp(&pid, argv[0].c_str(), &actions, nullptr, cargv.data(), environ);
  posix_spawn_file_actions_destroy(&actions);

  // The parent never touches the ends the child owns, whether or not the
  // spawn actually succeeded.
  if (options.pipe_stdin) {
    close(stdin_pipe[0]);
    stdin_pipe[0] = -1;
  }
  if (options.pipe_stdout) {
    close(stdout_pipe[1]);
    stdout_pipe[1] = -1;
  }

  if (rc != 0) {
    return absl::InternalError(absl::StrCat("posix_spawnp(", argv[0], "): ", strerror(rc)));
  }

  Subprocess sp;
  sp.pid = pid;
  sp.stdin_fd = options.pipe_stdin ? stdin_pipe[1] : -1;
  sp.stdout_fd = options.pipe_stdout ? stdout_pipe[0] : -1;
  std::move(pipe_closer).Cancel();
  return sp;
}

int WaitForProcess(pid_t pid) {
  int status = 0;
  pid_t r;
  do {
    r = waitpid(pid, &status, 0);
  } while (r < 0 && errno == EINTR);
  if (r < 0 || !WIFEXITED(status)) {
    return -1;
  }
  return WEXITSTATUS(status);
}

}  // namespace unwind_analysis
