#encoding: utf-8


class CreateCasserverSts < ActiveRecord::Migration
  def self.up
    create_table :casserver_sts do |t|
      t.string    'ticket',            :null => false
      t.text      'service',           :null => false
      t.timestamp 'created_on',        :null => false
      t.datetime  'consumed',          :null => true
      t.string    'client_hostname',   :null => false
      t.string    'username',          :null => false
      t.string    'type',              :null => false
      t.integer   'granted_by_pgt_id', :null => true
      t.integer   'granted_by_tgt_id', :null => true
    end
  end

  def self.down
    drop_table :casserver_sts
  end
end
