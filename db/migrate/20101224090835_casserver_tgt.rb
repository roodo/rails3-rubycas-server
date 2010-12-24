class CasserverTgt < ActiveRecord::Migration
  def self.up
    create_table 'casserver_tgt', :force => true do |t|
      t.string    'ticket',           :null => false
      t.timestamp 'created_on',       :null => false
      t.string    'client_hostname',  :null => false
      t.string    'username',         :null => false
      t.text      'extra_attributes', :null => true
    end
  end

  def self.down
    drop_table 'casserver_tgt'
  end
end
