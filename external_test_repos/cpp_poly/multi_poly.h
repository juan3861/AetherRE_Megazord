#ifndef MULTI_POLY_H
#define MULTI_POLY_H

#ifdef _WIN32
#ifdef MULTI_EXPORTS
#define MULTI_API __declspec(dllexport)
#else
#define MULTI_API __declspec(dllimport)
#endif
#else
#define MULTI_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef void* HDEVICE;
typedef void* HREADER;
typedef void* HWRITER;

MULTI_API HDEVICE create_dual_device(int initial_val);
MULTI_API int read_from_device(HREADER reader);
MULTI_API void write_to_device(HWRITER writer, int val);
MULTI_API void destroy_dual_device(HDEVICE device);

#ifdef __cplusplus
}
#endif

#endif // MULTI_POLY_H
