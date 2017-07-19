#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

require "hashsucc"

module Inject
  def inject(n)
    each do |value|
      n = yield(n, value)
    end
    n
  end

  def product(initial=1)
    inject(initial) { |n, value| n * value }
  end
end

class Array
  include Inject
end

class Bayespam
  attr_reader :probhash
  attr_writer :cache
  attr_writer :verbose

  # Simple constructor
  def initialize()
    @probhash = Hash.new
    @verbose  = nil
  end

  # Reads probability cache from dbfile. Probability pairs
  # are stored as keyword\tprobability with one record per line.
  def read_cache(dbfile)
    if test(?e, dbfile)
      File.open(dbfile, "r") do |fh|
        fh.each do |line|
	  line.chomp!
	  key, val = line.split("\t")
	  @probhash[key] = val.to_f
	end
        return @probhash
      end
    end
  end

  # Writes probability database to dbfile. Probability pairs
  # are stored as keyword\tprobability with one record per line.
  def write_cache(dbfile)
    if dbfile
      File.open(dbfile, "w") do |fh|
        @probhash.each do |key, val|
	  fh.puts "#{key}\t#{val}"
	end
      end
    end
  end

  # Scans one line at a time and breaks lines into interesting tokens. Each time
  # a token is seen, it's count is incremented by the succ! method.
  def tokenizer(fh)
    hash    = Hash.new(0)
    token   = "[A-Za-z$][A-Za-z0-9$'.-]+[A-Za-z0-9$]" # something interesting
    b64     = Regexp.compile("^[A-Za-z0-9/+]+$") # precompile for speed
    tok     = Regexp.compile(token) # precompile for speed

    fh.each do |data|
      # Remove pesky newlines
      data.chomp!
      # Base64 decode Base64 encoded lines
      data = data =~ b64 ? data.unpack("m*").to_s : data
      hash.succ! data.scan(tok)
    end
    hash
  end

  # Returns the result of feeding a file into the tokenizer.
  def token_freq_file(filename) 
    hash = {}
    File.open(filename) do |f|
      hash = tokenizer(f)
    end
    GC.start
    yield hash if block_given?
    hash
  end

  # Returns the result of feeding an entire directory into the tokenizer.
  def token_freq_dir(directory) 
    hash = {}
    Dir.open(directory) do |dir|
      dir.each do |file|
        next if file =~ /^\./
        File.open(directory + '/' + file) do |f|
          hash.update(tokenizer(f))
        end
      end
    end
    GC.start
    yield hash if block_given?
    hash
  end

  # Counts the number of messages in a given file.
  def message_count(file)
    test(?d, file) ? 
      Dir.entries(file).delete_if {|x| x =~ /^\./}.length :
      File.open(file, "r").read.scan(/^From /m).length
  end

  # Constructs a hash of keywords and their associated probability of being spam.
  def probability(taint, clean)
    taintcount = message_count(taint).to_f
    tainthash = test(?d, taint) ? token_freq_dir(taint) : token_freq_file(taint)
    cleancount = message_count(clean).to_f
    cleanhash = test(?d, clean) ? token_freq_dir(clean) : token_freq_file(clean)

    (cleanhash.keys & tainthash.keys).each do |t|
      cleanhash[t] ||= 0.0
      tainthash[t] ||= 0.0
      g = 2 * (cleanhash[t] || 0.0).to_f
      b = (tainthash[t] || 0.0).to_f

      unless (g + b < 5)
        @probhash[t] =
          [
             [ [b / taintcount, 1.0].min /
                    ([g / cleancount, 1.0].min + [b / taintcount, 1.0].min), .99
             ].min, .01
          ].max
      end
    end
    @probhash
  end
  
  # Calculates combined probability when given a set of probabilities.
  def combined_probability(probs)
    prod = probs.product
    prod / (prod + probs.map {|x| 1 - x}.product)
  end

  # Determines the probability of a message being spam or nonspam.
  def message_probability(fh)
    mhash = {}
    tokenizer(fh).keys.each do |key|
      mhash[key] = @probhash[key] || .4
    end

    probs = mhash.values.sort { |a,b| (b - .5).abs <=> (a - .5).abs }[0,15]
    if @verbose
      mhash.each do |k,v| 
        if probs.include?(v) and v != 0.4
          puts "#{k} #{v}"
        end
      end
    end
    combined_probability(probs)
  end
end
