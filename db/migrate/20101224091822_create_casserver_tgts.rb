#encoding: utf-8


class CreateCasserverTgts < ActiveRecord::Migration
  def self.up
    create_table :casserver_tgts do |t|
      t.string    'ticket',           :null => false
      t.timestamp 'created_on',       :null => false
      t.string    'client_hostname',  :null => false
      t.string    'username',         :null => false
      t.text      'extra_attributes', :null => true
    end
  end

  def self.down
    drop_table :casserver_tgts
  end
end
