const std = @import("std");
const net = std.net;
const mem = std.mem;

const NetworkError = error{ PathNotFound, InvalidHTTPStructure, OutOfMemory };
const OK_STATUS = "200 OK";
const NOT_FOUND = "404 Not Found";
const INTERNAL_ERROR = "500 Internl Server Error";

const Headers = std.StringHashMap([]const u8);
const HttpResponse = struct {
    const Self = @This();
    protocol: []const u8 = "HTTP/1.1",
    status: []const u8 = undefined,
    headers: Headers,
    body: []const u8,
    allocator: mem.Allocator,

    pub fn init(allocator: mem.Allocator) !Self {
        return .{ .protocol = "HTTP/1.1", .status = undefined, .headers = Headers.init(allocator), .body = try allocator.alloc(u8, 100), .allocator = allocator };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.body);
        self.headers.deinit();
    }

    pub fn writeResponse(self: *Self, conn: net.Server.Connection) !void {
        _ = try conn.stream.writer().print("{s} {s}\r\n", .{ self.protocol, self.status });
        var headers = self.headers.iterator();
        while (headers.next()) |header| {
            _ = try conn.stream.writer().print("{s}: {s}\r\n", .{ header.key_ptr.*, header.value_ptr.* });
        }
        _ = try conn.stream.write("\r\n");
        _ = try conn.stream.writer().print("{s}", .{self.body});
    }
};

const HttpRequest = struct {
    const Self = @This();

    path: []const u8,
    method: []const u8,
    protocol: []const u8,
    headers: Headers,
    body: []u8,
    allocator: mem.Allocator,
    pub fn init(allocator: mem.Allocator) Self {
        return .{ .path = undefined, .method = undefined, .protocol = undefined, .headers = Headers.init(allocator), .body = undefined, .allocator = allocator };
    }
    pub fn deinit(self: *Self) void {
        self.allocator.free(self.body);
        self.headers.deinit();
    }
    pub fn bufferInit(buffer: []const u8, allocator: mem.Allocator) NetworkError!Self {
        var self = Self.init(allocator);
        var content = std.mem.splitSequence(u8, buffer, "\r\n");
        const req_line = content.next();
        try self.parseRequestLine(req_line);

        try self.setHeaders(&content);
        return self;
    }

    fn parseRequestLine(self: *Self, request_line: ?[]const u8) NetworkError!void {
        if (request_line) |req_line| {
            var req_line_parts = std.mem.splitScalar(u8, req_line, ' ');
            const method = req_line_parts.next();
            if (method) |m| {
                self.method = m;
            } else {
                return NetworkError.InvalidHTTPStructure;
            }

            const req_path = req_line_parts.next();
            if (req_path) |path| {
                self.path = path;
            } else {
                return NetworkError.InvalidHTTPStructure;
            }

            const protocol = req_line_parts.next();
            if (protocol) |proto| {
                if (!mem.eql(u8, proto, "HTTP/1.1")) {
                    return NetworkError.InvalidHTTPStructure;
                }

                self.protocol = proto;
            } else {
                return NetworkError.InvalidHTTPStructure;
            }
        } else {
            return NetworkError.InvalidHTTPStructure;
        }
    }

    fn setHeaders(self: *Self, headers: *mem.SplitIterator(u8, .sequence)) NetworkError!void {
        var header_list = Headers.init(self.allocator);
        while (headers.next()) |header| {
            if (header.len == 0)
                break;
            var header_parts = mem.splitScalar(u8, header, ':');
            const key = header_parts.next();
            const value = header_parts.next();

            if (key == null or value == null) {
                return NetworkError.InvalidHTTPStructure;
            } else {
                try header_list.put(mem.trim(u8, key.?, " "), mem.trim(u8, value.?, " "));
            }
        }
        self.headers.deinit();
        self.headers = header_list;
    }
};

const HttpServer = struct {
    const Self = @This();
    allocator: mem.Allocator,
    file_dir: []const u8 = "./tmp",
    pub fn init(allocator: mem.Allocator) Self {
        return .{ .allocator = allocator };
    }

    pub fn listen(self: HttpServer, listener: *net.Server) !void {
        while (listener.accept()) |conn| {
            std.debug.print("client connected!\n", .{});
            const thread = try std.Thread.spawn(.{}, handleRequest, .{ self, conn });
            thread.detach();
        } else |err| {
            std.debug.print("error:\n{any}", .{err});
        }
    }
    fn handleRequest(self: HttpServer, conn: net.Server.Connection) !void {
        var response = try HttpResponse.init(self.allocator);
        defer response.deinit();

        var buffer: [4068]u8 = undefined;

        _ = try conn.stream.read(&buffer);
        defer conn.stream.close();

        std.debug.print("request: \n{s}", .{buffer});

        var try_request = HttpRequest.bufferInit(&buffer, self.allocator);
        if (try_request) |*request| {
            defer request.deinit();
            if (self.parsePath(request.*, &response)) {
                try response.writeResponse(conn);
            } else |err| {
                _ = try conn.stream.writer().print("HTTP/1.1 {s}\r\n\r\n", .{INTERNAL_ERROR});
                std.debug.print("ERROR WAS THROWN\n\n\n{any}", .{err});
            }
        } else |err| {
            _ = try conn.stream.writer().print("HTTP/1.1 {s}\r\n\r\n", .{INTERNAL_ERROR});
            std.debug.print("ERROR WAS THROWN\n\n\n{any}", .{err});
        }
    }

    fn parsePath(self: HttpServer, request: HttpRequest, response: *HttpResponse) NetworkError!void {
        if (std.mem.eql(u8, request.method, "POST")) {
            try self.handlePost(request, response);
            return;
        }
        if (std.mem.eql(u8, request.path, "/")) {
            response.status = OK_STATUS;
            return;
        } else if (std.mem.startsWith(u8, request.path, "/echo/")) {
            const first: usize = 6;
            const res = request.path[first..];
            response.status = OK_STATUS;
            try response.headers.put("Content-Type", "text/plain");
            const file_len = try std.fmt.allocPrint(self.allocator, "{d}", .{res.len});
            try response.headers.put("Content-Length", file_len);
            response.body = try std.fmt.allocPrint(self.allocator, "{s}", .{res});
            return;
        } else if (std.mem.eql(u8, request.path, "/user-agent")) {
            if (request.headers.get("User-Agent")) |res| {
                response.status = OK_STATUS;
                try response.headers.put("Content-Type", "text/plain");
                const file_len = try std.fmt.allocPrint(self.allocator, "{d}", .{res.len});
                try response.headers.put("Content-Length", file_len);
                response.body = res;
                return;
            } else {
                response.status = NOT_FOUND;
                return;
            }
        } else if (std.mem.startsWith(u8, request.path, "/files/")) {
            const dir = self.file_dir;
            const file_name = request.path[7..];

            std.debug.print("FILE_NAME:{s}/{s}", .{ dir, file_name });
            const directory = std.fs.openDirAbsolute(dir, .{}) catch {
                response.status = NOT_FOUND;
                return;
            };
            const file = directory.readFileAlloc(self.allocator, file_name, 4000) catch {
                response.status = NOT_FOUND;
                return;
            };
            response.status = OK_STATUS;
            try response.headers.put("Content-Type", "application/octet-stream");
            const file_len = try std.fmt.allocPrint(self.allocator, "{d}", .{file.len});
            try response.headers.put("Content-Length", file_len);
            response.body = file;
            return;
        } else {
            response.status = NOT_FOUND;
            return;
        }
    }

    pub fn handlePost(self: Self, request: HttpRequest, response: *HttpResponse) NetworkError!void {
        if (mem.startsWith(u8, request.path, "/write/")) {
            const dir = self.file_dir;
            const file_name = request.path[7..];
            const directory = std.fs.openDirAbsolute(dir, .{}) catch {
                response.status = NOT_FOUND;
                return;
            };
            const file = directory.createFile(file_name, .{}) catch {
                response.status = NOT_FOUND;
                return;
            };
            defer file.close();
            file.writeAll(request.body) catch {
                response.status = INTERNAL_ERROR;
                return;
            };
            response.status = OK_STATUS;
        }
    }
};

pub fn main() !void {
    var alloc = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = alloc.deinit();
    const allocator = alloc.allocator();
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    std.debug.print("Logs from your program will appear here!\n", .{});

    // Uncomment this block to pass the first stage
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    var nextDir: i16 = 0;
    var dir: []const u8 = undefined;
    while (args.next()) |arg| {
        if (nextDir == 1) {
            dir = arg;
            break;
        }
        if (mem.eql(u8, arg, "--directory")) {
            nextDir = 1;
        }
        std.debug.print("{s}", .{arg});
    }
    const address = try net.Address.resolveIp("127.0.0.1", 4221);
    var listener = try address.listen(.{
        .reuse_address = true,
    });
    defer listener.deinit();
    var server = HttpServer.init(allocator);
    if (nextDir == 1) {
        server.file_dir = dir;
    }
    try server.listen(&listener);
}
