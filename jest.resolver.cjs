module.exports = (request, options) => {
  const resolve = options.defaultResolver;
  try {
    return resolve(request, options);
  } catch (err) {
    if (request.endsWith('.js')) {
      const fallbackRequest = request.replace(/\.js$/, '.ts');
      try {
        return resolve(fallbackRequest, options);
      } catch (_err) {
        // ignore and throw original error below
      }
    }
    throw err;
  }
};
