#encoding: utf-8

class CreateTicketGrantingTickets < ActiveRecord::Migration
  def self.up
    create_table :ticket_granting_tickets do |t|
      t.string    'ticket',           :null => false
      t.timestamp 'created_on',       :null => false
      t.string    'client_hostname',  :null => false
      t.string    'username',         :null => false
      t.text      'extra_attributes', :null => true
    end
  end

  def self.down
    drop_table :ticket_granting_tickets
  end
end
