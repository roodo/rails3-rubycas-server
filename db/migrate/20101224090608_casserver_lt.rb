class CasserverLt < ActiveRecord::Migration
  def self.up
    create_table 'casserver_lt', :force => true do |t|
      t.string    'ticket',          :null => false
      t.timestamp 'created_on',      :null => false
      t.datetime  'consumed',        :null => true
      t.string    'client_hostname', :null => false
    end
  end

  def self.down
    drop_table 'casserver_lt'
  end
end
