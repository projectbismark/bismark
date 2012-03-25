#!/usr/bin/env lua

require('os')
require('io')
require('table')
require('bmlua.str')
require('bmlua.tbl')
require('math')

MSTATS_STRICT_PARSE_ERROR = -1000

function usage(me)
    print(string.format(
            "USAGE: %s param toolname src_ip dst_ip exit_status [direction]",
            me))
    print("  where a string of real numbers, one per line, is provided to " ..
          "standard input")
    os.exit(2)
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
    if not strict then strict = true end  -- strict=true by default
    count = 0
    mean = 0
    -- sample variance computed by Welford's method
    -- see Knuth's The Art of Computer Programming v.2, 2ed, page 232
    M2 = 0
    variance = nil
    data = {}

    while true do
        line = io.read('*line')
        if line == nil then break end
        element = tonumber(bmlua.str.strip(line))
        if element then
            data[#data+1] = element
            count = count + 1
            delta = element - mean
            mean = mean + delta/count
            M2 = M2 + delta*(element - mean)
        elseif strict then
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
    print_xml(measure_attrs)
end

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

function print_xml(attrs)
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
    else
        kwargs = {param=argv[1],
                  tool=argv[2],
                  srcip=argv[3],
                  dstip=argv[4],
                  exitstatus=argv[5]}
        generate_output(kwargs, parse_stdin())
    end
end

return main(arg)
