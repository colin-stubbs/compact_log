local THREAD_COUNT = 10

local counter = 0
local threads = {}

local leafs = nil
local leaf_count = 0
local thread_id = 0
local ca_base64 = nil

local function extract_base64_from_pem(pem)
    return pem:gsub("%-%-%-%-%-BEGIN CERTIFICATE%-%-%-%-%-", "")
              :gsub("%-%-%-%-%-END CERTIFICATE%-%-%-%-%-", "")
              :gsub("\n", "")
              :gsub("\r", "")
              :gsub("%s", "")
end

function setup(thread)
    thread:set("id", counter)
    table.insert(threads, thread)
    counter = counter + 1
end

function init(args)
    thread_id = id
    
    local ca_file = io.open("./certs/ca.pem", "r")
    if ca_file then
        local ca_pem = ca_file:read("*all")
        ca_file:close()
        ca_base64 = extract_base64_from_pem(ca_pem)
    else
        print("ERROR: Could not load ca.pem")
        os.exit(1)
    end
    
    leafs = {}
    
    local leaf_file_path = string.format("./certs/leafs_thread_%d.pem", thread_id)
    
    local f = io.open(leaf_file_path, "r")
    if f then
        local content = f:read("*all")
        f:close()
        
        local in_cert = false
        local current_cert = ""
        
        for line in content:gmatch("[^\n]+") do
            if line:match("^%-%-%-%-%-BEGIN CERTIFICATE%-%-%-%-%-") then
                in_cert = true
                current_cert = line .. "\n"
            elseif line:match("^%-%-%-%-%-END CERTIFICATE%-%-%-%-%-") then
                current_cert = current_cert .. line
                local base64_cert = extract_base64_from_pem(current_cert)
                leafs[#leafs + 1] = base64_cert
                in_cert = false
                current_cert = ""
            elseif in_cert then
                current_cert = current_cert .. line .. "\n"
            end
        end
        
        leaf_count = #leafs
        print(string.format("Thread %d: Loaded %d leaf certificates from %s", 
                          thread_id, leaf_count, leaf_file_path))
    else
        print(string.format("ERROR: Thread %d could not load %s", thread_id, leaf_file_path))
        print("Please run: cargo run --release --bin gen_certs -- <num_certs> ./certs")
        os.exit(1)
    end
end

local function build_json(leaf_base64)
    local json = '{"chain":["' .. leaf_base64 .. '","' .. ca_base64 .. '"]}'
    return json
end

local request_counter = 0

function request()
    request_counter = request_counter + 1
    local index = ((request_counter - 1) % leaf_count) + 1
    local leaf = leafs[index]
    
    local body = build_json(leaf)
    local headers = {
        ["Content-Type"] = "application/json",
        ["Content-Length"] = string.len(body)
    }
    
    return wrk.format("POST", "/ct/v1/add-chain", headers, body)
end

function response(status, headers, body)
    if status ~= 200 then
    end
end
