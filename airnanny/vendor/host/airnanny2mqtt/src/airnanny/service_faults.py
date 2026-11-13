"""Bounded crash locations, without exception messages or frame contents."""
import re

FRAME_LIMIT = 12


def _name(value):
    # Names come from code objects, never from exception arguments. Validate
    # again when displaying a saved record; do not print arbitrary JSON fields.
    if isinstance(value, str) and re.fullmatch(r'[A-Za-z_<>][A-Za-z0-9_.<>-]{0,119}', value):
        return value
    return '<unknown>'


def exception_details(exc):
    """Copy locations only; never stringify the exception or retain a frame."""
    frames = []
    tb = exc.__traceback__
    while tb is not None:
        code = tb.tb_frame.f_code
        frames.append(dict(file=_name(code.co_filename.replace('\\', '/').rsplit('/', 1)[-1]),
                           function=_name(code.co_name), line=tb.tb_lineno))
        frames = frames[-FRAME_LIMIT:]
        tb = tb.tb_next
    return dict(exception_type=_name(type(exc).__name__), frames=frames)


def runtime_fault_lines(record):
    """Render only the diagnostic belonging to this latch, also after restart."""
    if record.get('reason') != 'service_runtime_fault':
        return []
    lines = []
    for field, title in (('runtime_fault', 'RUNTIME FAULT'),
                         ('runtime_cleanup_fault', 'CLEANUP FAULT')):
        detail = record.get(field)
        if not isinstance(detail, dict):
            if field == 'runtime_fault':
                lines.append(title + ': the failing version did not record the original exception')
            continue
        lines.append(title + ': ' + _name(detail.get('exception_type')))
        frames = detail.get('frames')
        if not isinstance(frames, list):
            continue
        for frame in frames[-FRAME_LIMIT:]:
            if not isinstance(frame, dict) or type(frame.get('line')) is not int or frame['line'] <= 0:
                continue
            lines.append('  at %s:%d in %s' %
                         (_name(frame.get('file')), frame['line'], _name(frame.get('function'))))
    return lines
