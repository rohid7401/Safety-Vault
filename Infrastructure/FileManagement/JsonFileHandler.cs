using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;

namespace PasswordManager.Infrastructure.FileManagement
{
    // Handles reading and writing password entries to a JSON file.
    public class JsonFileHandler<T>
    {
        private readonly JsonSerializerOptions _serializerOptions = new JsonSerializerOptions
        {
            WriteIndented = true
        };

        public async Task<List<T>> ReadEntriesAsync(string filePath)
        {
            if (!File.Exists(filePath))
                return new List<T>();

            using var stream = File.OpenRead(filePath);
            return await JsonSerializer.DeserializeAsync<List<T>>(stream, _serializerOptions)
                   ?? new List<T>();
        }

        public async Task WriteEntriesAsync(string filePath, List<T> entries)
        {
            using var stream = File.Create(filePath);
            await JsonSerializer.SerializeAsync(stream, entries, _serializerOptions);
        }
    }
}
