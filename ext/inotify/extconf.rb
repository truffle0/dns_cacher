#!/bin/env ruby
require 'mkmf'
extension_name = "inotify_sys"

dir_config extension_name
create_makefile extension_name
