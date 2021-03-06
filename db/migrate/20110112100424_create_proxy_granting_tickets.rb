#encoding: utf-8

class CreateProxyGrantingTickets < ActiveRecord::Migration
  def self.up
    create_table :proxy_granting_tickets do |t|
      t.string    'ticket',            :null => false
      t.timestamp 'created_on',        :null => false
      t.string    'client_hostname',   :null => false
      t.string    'iou',               :null => false
      t.integer   'service_ticket_id', :null => false
    end
  end

  def self.down
    drop_table :proxy_granting_tickets
  end
end
