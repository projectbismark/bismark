#!/usr/bin/env lua

require('os')
require('io')
require('table')
require('bmlua.str')
require('bmlua.tbl')
require('math')

MSTATS_STRICT_PARSE_ERROR = -1000

-- Print usage information.
function usage(me)
    print(string.format(
[[USAGE: %s param toolname src_ip dst_ip exit_status [direction]
  where a series of real numbers, one per line, is provided to standard input
  to be summarized by %s]], me, me))
end

-- Parse number-per-line from standard input and output table and some
-- statistics. The parser has two modes:
--   * strict:     returns nil if the data is improperly formatted (contains
--                 anything other than a single number per line with no blank
--                 lines).
--   * not strict: improperly formatted lines are ignored, and do not
--                 contribute to the data table or statistics
--
-- strict - boolean, whether or not the parser should be strict.
--          Defaults to true.
--
-- Returns data table (or nil in case of error and strict parsing),
--         number of elements in table,
--         mean of the elements in the table
--         sample variance of the elements in the table
function parse_stdin(strict)
    if strict == nil then strict = true end  -- strict=true by default
    data = {}
    count = 0
    mean = 0
    M2 = 0
    variance = nil

    while true do
        line = io.read('*line')
        if line == nil then break end
        element = tonumber(bmlua.str.strip(line))
        if element then
            data[#data+1] = element
            count = count + 1
            -- sample variance computed by Welford's method
            -- see Knuth's The Art of Computer Programming v.2, 2ed, page 232
            delta = element - mean
            mean = mean + delta/count
            M2 = M2 + delta*(element - mean)
        elseif strict then
            -- we hit a bad row, and strict parsing is enabled -- return nil
            data = nil
            break
        end
    end

    if count > 1 then
        variance = M2/(count - 1)
    elseif count == 1 then
        variance = 0
    end

    if data then
        table.sort(data)
    end

    return data, count, mean, variance
end

-- Compute statistics on data and print XML measurement output. If no data is
-- present, change exitstatus to value of MSTATS_STRICT_PARSE_ERROR.
--
-- kwargs   - a table containing attributes and their values to be included in
--            the XML element.
-- data     - a table containing data to be summarized.
-- count    - the number of data items processed.
-- mean     - the arithmetic mean of data.
-- variance - the sample variance of data.
function generate_output(kwargs, data, count, mean, variance)
    measure_attrs = {}
    for k,v in pairs(kwargs) do measure_attrs[k] = v end
    measure_attrs['count'] = count
    measure_attrs['timestamp'] = os.date('%s')
    if data then
        if #data > 0 then
            measure_attrs['avg'] = mean
            measure_attrs['std'] = variance ^ 0.5
            measure_attrs['min'] = data[1]
            measure_attrs['max'] = data[#data]
            measure_attrs['med'], lindex, uindex = median(data)
            if count > 1 then
                measure_attrs['iqr'] = (
                        median(bmlua.tbl.islice(data, uindex, #data)) -
                        median(bmlua.tbl.islice(data, 1, lindex)))
            else
                measure_attrs['iqr'] = 0
            end
        end
    else
        measure_attrs['exitstatus'] = MSTATS_STRICT_PARSE_ERROR
    end
    print_measurement_xml(measure_attrs)
end

-- Compute the median of a sorted table.
--
-- t - table containing a sorted list of items
--
-- Returns the median value of the table,
--         the lower index of the value used to compute the median,
--         the upper index of the value used to compute the median.
-- In the case that the table has an odd number of items, the lower and upper
-- index contain the same value.
function median(t)
    if #t % 2 == 0 then
        lindex = math.floor(#t/2)
        uindex = lindex + 1
        med = (t[lindex] + t[uindex]) / 2
        return med, lindex, uindex
    else
        mindex = math.floor(#t/2)+1
        med = t[mindex]
        return med, mindex, mindex
    end
end

-- Print a measurement XML entity containing the attributes and values
-- provided, ordered by attribute name.
--
-- attrs - a table containing attributes and values to be included in the XML
--         element.
function print_measurement_xml(attrs)
    io.write('    <measurement ')
    keys = {}
    for k in pairs(attrs) do
        keys[#keys+1] = k
    end
    table.sort(keys)
    for i,k in ipairs(keys) do
        io.write(string.format('%s=%q ', k, attrs[k]))
    end
    io.write('/>\n')
end


function main(argv)
    if #argv < 5 then
        usage(argv[0])
        os.exit(2)
    end
    kwargs = {param=argv[1],
              tool=argv[2],
              srcip=argv[3],
              dstip=argv[4],
              exitstatus=argv[5]}
    if #argv == 6 then
        kwargs['direction'] = argv[6]
    end
    generate_output(kwargs, parse_stdin())
end

return main(arg)
