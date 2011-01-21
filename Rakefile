# Add your own tasks in files placed in lib/tasks ending in .rake,
# for example lib/tasks/capistrano.rake, and they will automatically be available to Rake.

require File.expand_path('../config/application', __FILE__)
require 'rake'

RoodoCasServer::Application.load_tasks


namespace :app do
  namespace :server do
    
    desc 'start the server'
    task :start do
      sh 'unicorn_rails -D -c config/unicorn.rb'
    end
    
    desc 'stop the server'
    task :stop do
      sh 'kill -term `cat tmp/pids/unicorn.pid`'
    end
    
    desc 'restart the server'
    task :restart do
      sh 'kill -HUP `cat tmp/pids/unicorn.pid`'
    end
    
    desc 'reload the server'
    task :restart do
      sh 'kill -HUP `cat tmp/pids/unicorn.pid`'
    end
    
  end
end