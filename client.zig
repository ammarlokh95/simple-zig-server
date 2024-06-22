const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();
    try createClient(allocator);
}

fn createClient(allocator: std.mem.Allocator) !void {
    const http = std.http;

    var client = http.Client{ .allocator = allocator };
    defer client.deinit();
    // Parse the URI.
    const uri = std.Uri.parse("https://whatthecommit.com/index.txt") catch unreachable;

    // Create the headers that will be sent to the server.
    var headers = std.http.Header{ .name = "accepts", .value = "*/*" };
    defer headers.deinit();

    const requestOptions = http.Client.RequestOptions{ .headers = headers };
    // Create a request.
    var request = try client.open(.GET, uri, requestOptions);
    defer request.deinit();

    // sent the request
    try request.start();

    // await response from serverr
    // -- handles redirects
    // -- reading and storing headers
    // -- setting up decompression
    try request.wait();

    // Read the entire response body, but only allow it to allocate 8 kb of mem
    const body = request.reader().readAllAlloc(allocator, 8192) catch unreachable;
    defer allocator.free(body);

    std.log.info("{s}", .{body});
}
