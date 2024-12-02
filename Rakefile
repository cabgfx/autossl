require 'bundler/audit/task'

# Rake task for running bundler-audit
Bundler::Audit::Task.new do |task|
  task.name = :audit
  task.fail_on_issues = true
  task.verbose = true
end

# Default task to run all audits
task default: :audit
