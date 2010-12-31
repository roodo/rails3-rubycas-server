#encoding: utf-8



class CreateUsers < ActiveRecord::Migration
  def self.up
    create_table :users do |t|
      t.string 'username',       :null => false
      t.string 'password',       :null => false
      t.timestamps 'created_at', :null => false
      t.timestamps 'updated_at', :null => false
    end
  end

  def self.down
    drop_table :users
  end
end
