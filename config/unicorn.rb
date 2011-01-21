#encoding: utf-8


ENV['RAILS_ENV'] = 'development'
worker_processes 1
listen 3000, :tries => 200

timeout 30

root = File.expand_path(File.dirname(__FILE__)).split('/')[0..-2].join('/')
pid(root + '/tmp/pids/unicorn.pid')
working_directory root
stderr_path(root + '/log/unicorn.stderr.log')
stdout_path(root + '/log/unicorn.stdout.log')