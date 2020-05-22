#include <boost/asio.hpp>

struct composed_echo_op
{
	Buffer m_buffer;
	Socket m_socket;
	Callback m_callback
	void operator()(socket, buffer, cb)
	{
		m_buffer = buffer;
		m_socker = socket;
		m_callback = cb;
		p_step1();
	}
	void step1() {
		async_read(m_socket, m_buffer, [this](ErrorCode& err)
		{
			if(err) {
				m_callback(err);
				return;
			}
			step2();
		});
	}
	void step2() {
		async_write(m_socket, m_buffer, [this](ErrorCode& err)
		{
			if(err) {
				m_callback(err);
				return;
			}
			step1();
		});		
	}
}