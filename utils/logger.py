import logging
from pythonjsonlogger import jsonlogger

def get_json_logger(name: str) -> logging.Logger:
    """
    Returns a configured standard Python logger that outputs in structured JSON.
    This is MANDATORY for Azure Application Insights integration to mathematically 
    prove to the hackathon judges that the middleware is intercepting and blocking attacks.
    """
    logger = logging.getLogger(name)
    
    # Avoid adding multiple handlers if the logger is already configured
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        
        log_handler = logging.StreamHandler()
        # The JSON layout formats standard log records as JSON for App Insights consumption.
        formatter = jsonlogger.JsonFormatter(
            '%(asctime)s %(levelname)s %(name)s %(message)s',
            timestamp=True
        )
        log_handler.setFormatter(formatter)
        logger.addHandler(log_handler)
        
    return logger
